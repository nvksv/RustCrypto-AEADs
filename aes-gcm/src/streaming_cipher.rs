//! Core AEAD cipher implementation for (X)ChaCha20Poly1305.

use super::*;

use core::marker::PhantomData;

use ::cipher::{BlockSizeUser, BlockCipherEncrypt, BlockCipherEncClosure, BlockCipherDecrypt, BlockCipherDecClosure};
use aead::{inout::InOutBuf, Error, AeadFinalize};
use ghash::{GHash, universal_hash::{KeyInit, UniversalHash, Key, Block}};
use cipher::{
    InnerIvInit, StreamCipherCore,
    array::{Array, ArraySize},
    consts::U16,
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
    Aes: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt + BlockCipherDecrypt,
    TagSize: super::TagSize,
{
    direction: Direction,
    ctr: Ctr32BE<Aes>,
    mask: ghash::Block,
    ghash: GHash,
    mode: CipherState,
    associated_data_length: u64,
    data_length: 0,
    #[cfg(not(feature = "zeroize"))] 
    associated_data_buffer: [0;BLOCK_SIZE],
    #[cfg(feature = "zeroize")] 
    associated_data_buffer: Zeroizing::new([0;BLOCK_SIZE]),
    associated_data_buffer_pos: 0,
    data_length: u64,
    _ph: PhantomData<TagSize>,
}

impl<Aes, TagSize> StreamingCipher<Aes, TagSize>
where
    Aes: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt + BlockCipherDecrypt + Clone,
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
        let (ctr, mask) = Self::init_ctr( cipher, nonce);

        Self { 
            direction,
            ctr: ctr.clone(),
            mask, 
            ghash: cipher.ghash.clone(), 
            mode: CipherState::AfterNonce,
            associated_data_length: 0,
            data_length: 0,
            _ph: PhantomData,
        }
    }
}

impl<Aes, TagSize> BlockSizeUser for StreamingCipher<Aes, TagSize>
where
    Aes: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt + BlockCipherDecrypt,
    TagSize: super::TagSize,
{
    type BlockSize = Aes::BlockSize;
}

impl<Aes, TagSize> StreamingCipher<Aes, TagSize>
where
    Aes: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt + BlockCipherDecrypt,
    TagSize: super::TagSize,
{
    /// Authenticate the lengths of the associated data and message
    fn authenticate_lengths(&mut self, associated_data_len: u64, buffer_len: u64) -> Result<(), Error> {

        let associated_data_bits = associated_data_len * 8;
        let buffer_bits = (buffer_len as u64) * 8;

        let mut block = ghash::Block::default();
        block[..8].copy_from_slice(&associated_data_bits.to_be_bytes());
        block[8..].copy_from_slice(&buffer_bits.to_be_bytes());
        self.ghash.update(&[block]);

        Ok(())
    }

    pub fn apply_associated_data( &mut self, associated_data: &[u8] ) -> Result<(), Error> {
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

        self.ghash.update( associated_data );

        Ok(())
    }
}

impl<Aes, TagSize> BlockCipherEncrypt for StreamingCipher<Aes, TagSize>
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
                self.ctr.apply_keystream_partial( buf.reborrow() );
                self.update_mac_buffer( buf.get_out() );
            },
            Direction::Decryption => {
                self.update_mac_buffer( buf.get_in() );
                self.ctr.apply_keystream_partial( buf );
            },
        }

        Ok(())
    }

}

impl<Aes, TagSize> AeadFinalize<TagSize> for StreamingCipher<Aes, TagSize>
where
    Aes: BlockSizeUser<BlockSize = U16> + BlockCipherEncrypt,
    TagSize: super::TagSize,
{
    fn finalize( mut self ) -> Result<Array<u8, TagSize>, Error> {
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
        
        Ok(self.mac.finalize())
    }

    fn verify( mut self, expected: &Array<u8, TagSize> ) -> Result<(), Error> {
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

        if self.mac.verify(expected).is_ok() {
            Ok(())
        } else {
            Err(Error)
        }
    }
}