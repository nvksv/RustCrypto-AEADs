//! Core AEAD cipher implementation for (X)ChaCha20Poly1305.

use super::*;

use core::marker::PhantomData;

use ::cipher::{BlockSizeUser};
use aead::{inout::InOutBuf, Error, AeadChunkedCipher};
use ghash::{GHash, universal_hash::{UniversalHash}};
use cipher::{
    array::{Array, ArraySize}, consts::U16, InnerIvInit, StreamCipher, StreamCipherCore, StreamCipherError, StreamCipherCoreWrapper,
};


#[cfg(feature = "zeroize")]
use zeroize::Zeroizing;

const BLOCK_SIZE: usize = 16;

#[derive(Debug, Clone, Copy)]
pub enum Direction {
    Encryption,
    Decryption
}

#[derive(Debug, PartialEq, Eq)]
enum CipherState {
    AfterNonce,
    AssociatedData,
    Data,
    Error,
}

/// AES-GCM instantiated with a particular nonce
pub struct StreamingCipher<Aes, TagSize>
where
    Aes: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt,
    TagSize: super::TagSize,
{
    direction: Direction,
    cipher: StreamCipherCoreWrapper<Ctr32BE<Aes>>,
    mask: ghash::Block,
    mac: GHash,
    mode: CipherState,
    associated_data_length: u64,
    data_length: u64,
    #[cfg(not(feature = "zeroize"))] 
    mac_buffer: [u8;BLOCK_SIZE],
    #[cfg(feature = "zeroize")] 
    mac_buffer: Zeroizing::new([u8;BLOCK_SIZE]),
    mac_buffer_pos: usize,
    _ph: PhantomData<TagSize>,
}

impl<Aes, TagSize> StreamingCipher<Aes, TagSize>
where
    Aes: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt + Clone,
    TagSize: super::TagSize,
{
    /// Initialize counter mode.
    ///
    /// See algorithm described in Section 7.2 of NIST SP800-38D:
    /// <https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf>
    ///
    /// > Define a block, J0, as follows:
    /// > If len(IV)=96, then J0 = IV || 0{31} || 1.
    /// > If len(IV) ≠ 96, then let s = 128 ⎡len(IV)/128⎤-len(IV), and
    /// >     J0=GHASH(IV||0s+64||[len(IV)]64).
    fn init_ctr<NonceSize: ArraySize>( cipher: &AesGcm<Aes, NonceSize, TagSize>, nonce: &Nonce<NonceSize>) -> (Ctr32BE<Aes>, ghash::Block) {
        let j0 = if NonceSize::to_usize() == 12 {
            let mut block = ghash::Block::default();
            block[..12].copy_from_slice(nonce);
            block[15] = 1;
            block
        } else {
            let mut ghash = cipher.ghash.clone();
            ghash.update_padded(nonce);

            let mut block = ghash::Block::default();
            let nonce_bits = (NonceSize::to_usize() as u64) * 8;
            block[8..].copy_from_slice(&nonce_bits.to_be_bytes());
            ghash.update(&[block]);
            ghash.finalize()
        };

        let mut ctr = Ctr32BE::inner_iv_init(cipher.cipher.clone(), &j0);
        let mut tag_mask = ghash::Block::default();
        ctr.write_keystream_block(&mut tag_mask);
        (ctr, tag_mask)
    }

    /// Instantiate the underlying cipher with a particular nonce
    pub(crate) fn new<NonceSize: ArraySize>( cipher: &super::AesGcm<Aes, NonceSize, TagSize>, nonce: &Nonce<NonceSize>, direction: Direction ) -> Self {
        let (ctr, mask) = Self::init_ctr( cipher, nonce );

        Self { 
            direction,
            cipher: StreamCipherCoreWrapper::from_core(ctr.clone()),
            mask, 
            mac: cipher.ghash.clone(), 
            mode: CipherState::AfterNonce,
            associated_data_length: 0,
            mac_buffer: [0;BLOCK_SIZE],
            mac_buffer_pos: 0,
            data_length: 0,
            _ph: PhantomData,
        }
    }
}

impl<Aes, TagSize> BlockSizeUser for StreamingCipher<Aes, TagSize>
where
    Aes: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt,
    TagSize: super::TagSize,
{
    type BlockSize = Aes::BlockSize;
}

impl<Aes, TagSize> StreamingCipher<Aes, TagSize>
where
    Aes: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt,
    TagSize: super::TagSize,
{
    /// Authenticate the lengths of the associated data and message
    fn authenticate_lengths(&mut self, associated_data_len: u64, buffer_len: u64) -> Result<(), Error> {

        let associated_data_bits = associated_data_len * 8;
        let buffer_bits = (buffer_len as u64) * 8;

        let mut block = ghash::Block::default();
        block[..8].copy_from_slice(&associated_data_bits.to_be_bytes());
        block[8..].copy_from_slice(&buffer_bits.to_be_bytes());
        self.mac.update(&[block]);

        Ok(())
    }

    fn update_mac_buffer( &mut self, mut data: &[u8] ) {
        if data.len() == 0 {
            return;
        }

        if self.mac_buffer_pos == 0 && data.len() % BLOCK_SIZE == 0 {
            let (blocks, tail) = Array::slice_as_chunks( data );
            debug_assert!( tail.len() == 0 );

            self.mac.update(blocks);
            return;
        }

        if self.mac_buffer_pos > 0 {
            let mac_buffer_rem = core::cmp::min( BLOCK_SIZE - self.mac_buffer_pos, data.len() );

            let head;
            (head, data) = data.split_at( mac_buffer_rem );
            debug_assert!( head.len() == mac_buffer_rem );

            let dst = &mut self.mac_buffer[self.mac_buffer_pos..(self.mac_buffer_pos+mac_buffer_rem)];

            dst.copy_from_slice( head );
            self.mac_buffer_pos += mac_buffer_rem;
            debug_assert!( self.mac_buffer_pos <= BLOCK_SIZE );

            if self.mac_buffer_pos == BLOCK_SIZE {
                #[cfg(not(feature = "zeroize"))] 
                let mac_buffer = &self.mac_buffer;
                #[cfg(feature = "zeroize")] 
                let mac_buffer = &*self.mac_buffer;

                let (blocks, tail) = Array::slice_as_chunks( mac_buffer );
                debug_assert!( tail.len() == 0 );

                self.mac.update( blocks );
                self.mac_buffer_pos = 0;
            };

            if data.len() == 0 {
                return;
            }

            debug_assert!( self.mac_buffer_pos == 0 );
        }

        let (blocks, tail) = Array::slice_as_chunks( data );
        self.mac.update( blocks );

        if tail.len() > 0 {
            let dst = &mut self.mac_buffer[..tail.len()];
            dst.copy_from_slice( tail );
            self.mac_buffer_pos = tail.len();
        }
    }

    fn finalize_mac_buffer( &mut self ) {
        if self.mac_buffer_pos == 0 {
            return;
        }

        #[cfg(not(feature = "zeroize"))] 
        let mac_buffer = &self.mac_buffer[..self.mac_buffer_pos];
        #[cfg(feature = "zeroize")] 
        let mac_buffer = &self.mac_buffer[..self.mac_buffer_pos];

        self.mac.update_padded( mac_buffer );
        self.mac_buffer_pos = 0;
    }

}

impl<Aes, TagSize> StreamCipher for StreamingCipher<Aes, TagSize>
where
    Aes: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt,
    TagSize: super::TagSize,
{
    /// Apply keystream to `inout` data.
    ///
    /// If end of the keystream will be achieved with the given data length,
    /// method will return [`StreamCipherError`] without modifying provided `data`.
    fn try_apply_keystream_inout(
        &mut self,
        mut buf: InOutBuf<'_, '_, u8>,
    ) -> Result<(), StreamCipherError> {
        match self.mode {
            CipherState::AfterNonce => {
                self.mode = CipherState::Data;
            },
            CipherState::AssociatedData => {
                self.finalize_mac_buffer();
                self.mode = CipherState::Data;
            },
            CipherState::Data => {},
            CipherState::Error => {
                return Err(StreamCipherError);
            }
        }

        self.data_length += buf.len() as u64;

        match self.direction {
            Direction::Encryption => {
                self.cipher.apply_keystream_inout( buf.reborrow() );
                self.update_mac_buffer( buf.get_out() );
            },
            Direction::Decryption => {
                self.update_mac_buffer( buf.get_in() );
                self.cipher.apply_keystream_inout( buf );
            },
        }

        Ok(())
    }

}

impl<Aes> AeadChunkedCipher for StreamingCipher<Aes, U16>
where
    Aes: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt,
{
    type TagSize = U16;

    fn apply_associated_data( &mut self, associated_data: &[u8] ) -> Result<(), Error> {
        match self.mode {
            CipherState::AfterNonce => {
                self.mode = CipherState::AssociatedData;
            },
            CipherState::AssociatedData => {},
            CipherState::Data | CipherState::Error => {
                self.mode = CipherState::Error;
                return Err(Error);
            }
        }

        self.associated_data_length += associated_data.len() as u64;

        self.update_mac_buffer( associated_data );

        Ok(())
    }

    fn finalize( mut self ) -> Result<Array<u8, U16>, Error> {
        match self.mode {
            CipherState::AfterNonce => {
                debug_assert!( self.mac_buffer_pos == 0 );
            },
            CipherState::AssociatedData | CipherState::Data => {
                self.finalize_mac_buffer();
            },
            CipherState::Error => {
                return Err(Error);
            }
        }

        self.authenticate_lengths( self.associated_data_length, self.data_length )?;
        
        let mut tag = self.mac.finalize();
        for (a, b) in tag.as_mut_slice().iter_mut().zip(self.mask.as_slice()) {
            *a ^= *b;
        }

        Ok(tag)
    }

    fn verify( self, expected: &Array<u8, U16> ) -> Result<(), Error> {
        let tag = self.finalize()?;

        use subtle::ConstantTimeEq;
        if expected[..16].ct_eq(&tag).into() {
            Ok(())
        } else {
            Err(Error)
        }
    }
}