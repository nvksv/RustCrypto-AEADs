//! Core AEAD cipher implementation for (X)ChaCha20Poly1305.

use ::cipher::{StreamCipher, StreamCipherSeek, StreamCipherError};
use aead::{Error, array::Array, inout::InOutBuf};
use poly1305::{
    Poly1305,
    universal_hash::{KeyInit, UniversalHash},
};
#[cfg(feature = "zeroize")]
use zeroize::Zeroizing;

use super::Tag;

/// Size of a ChaCha20 block in bytes
const BLOCK_SIZE: usize = 64;

/// Maximum number of blocks that can be encrypted with ChaCha20 before the
/// counter overflows.
const MAX_BLOCKS: usize = u32::MAX as usize;

#[derive(Debug, PartialEq, Eq)]
enum CipherMode {
    AfterNonce,
    AssociatedData,
    Data,
    Error,
}

/// ChaCha20Poly1305 instantiated with a particular nonce
pub struct Cipher<C>
where
    C: StreamCipher + StreamCipherSeek,
{
    cipher: C,
    mac: Poly1305,
    mode: CipherMode,
    associated_data_length: u64,
    data_length: u64,
    #[cfg(not(feature = "zeroize"))] 
    mac_buffer: [u8;BLOCK_SIZE],
    #[cfg(feature = "zeroize")] 
    mac_buffer: Zeroizing<[u8;BLOCK_SIZE]>,
    mac_buffer_pos: usize,
}

impl<C> Cipher<C>
where
    C: StreamCipher + StreamCipherSeek,
{
    /// Instantiate the underlying cipher with a particular nonce
    pub(crate) fn new(mut cipher: C) -> Self {
        // Derive Poly1305 key from the first 32-bytes of the ChaCha20 keystream
        let mut mac_key = poly1305::Key::default();
        cipher.apply_keystream(&mut mac_key);

        let mac = Poly1305::new(&mac_key);
        #[cfg(feature = "zeroize")]
        {
            use zeroize::Zeroize;
            mac_key.zeroize();
        }

        // Set ChaCha20 counter to 1
        cipher.seek(BLOCK_SIZE as u64);

        Self { 
            cipher, 
            mac, 
            mode: CipherMode::AfterNonce,
            associated_data_length: 0,
            data_length: 0,
            #[cfg(not(feature = "zeroize"))] 
            mac_buffer: [0;BLOCK_SIZE],
            #[cfg(feature = "zeroize")] 
            mac_buffer: Zeroizing::new([0;BLOCK_SIZE]),
            mac_buffer_pos: 0,
        }
    }

    /// Encrypt the given message in-place, returning the authentication tag
    pub fn encrypt_inout_detached(
        mut self,
        associated_data: &[u8],
        mut buffer: InOutBuf<'_, '_, u8>,
    ) -> Result<Tag, Error> {
        if self.mode != CipherMode::AfterNonce {
            self.mode = CipherMode::Error;
            return Err(Error);
        }

        if buffer.len() / BLOCK_SIZE >= MAX_BLOCKS {
            return Err(Error);
        }

        self.mac.update_padded(associated_data);

        // TODO(tarcieri): interleave encryption with Poly1305
        // See: <https://github.com/RustCrypto/AEADs/issues/74>
        self.cipher.apply_keystream_inout(buffer.reborrow());
        self.mac.update_padded(buffer.get_out());

        let associated_data_len: u64 = associated_data.len().try_into().map_err(|_| Error)?;
        let buffer_len: u64 = buffer.get_out().len().try_into().map_err(|_| Error)?;
        self.authenticate_lengths(associated_data_len, buffer_len)?;
        Ok(self.mac.finalize())
    }

    /// Decrypt the given message, first authenticating ciphertext integrity
    /// and returning an error if it's been tampered with.
    pub fn decrypt_inout_detached(
        mut self,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
        tag: &Tag,
    ) -> Result<(), Error> {
        if self.mode != CipherMode::AfterNonce {
            self.mode = CipherMode::Error;
            return Err(Error);
        }

        if buffer.len() / BLOCK_SIZE >= MAX_BLOCKS {
            return Err(Error);
        }

        self.mac.update_padded(associated_data);
        self.mac.update_padded(buffer.get_in());

        let associated_data_len: u64 = associated_data.len().try_into().map_err(|_| Error)?;
        let buffer_len: u64 = buffer.get_in().len().try_into().map_err(|_| Error)?;
        self.authenticate_lengths(associated_data_len, buffer_len)?;

        // This performs a constant-time comparison using the `subtle` crate
        if self.mac.verify(tag).is_ok() {
            // TODO(tarcieri): interleave decryption with Poly1305
            // See: <https://github.com/RustCrypto/AEADs/issues/74>
            self.cipher.apply_keystream_inout(buffer);
            Ok(())
        } else {
            Err(Error)
        }
    }

    /// Authenticate the lengths of the associated data and message
    fn authenticate_lengths(&mut self, associated_data_len: u64, buffer_len: u64) -> Result<(), Error> {

        let mut block = Array::default();
        block[..8].copy_from_slice(&associated_data_len.to_le_bytes());
        block[8..].copy_from_slice(&buffer_len.to_le_bytes());
        self.mac.update(&[block]);

        Ok(())
    }

    pub fn finalize( mut self ) -> Result<Tag, Error> {
        match self.mode {
            CipherMode::AfterNonce => {
                debug_assert!( self.mac_buffer_pos == 0 );
            },
            CipherMode::AssociatedData | CipherMode::Data => {
                self.finalize_mac_buffer();
            },
            CipherMode::Error => {
                return Err(Error);
            }
        }

        self.authenticate_lengths( self.associated_data_length, self.data_length )?;
        Ok(self.mac.finalize())
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
        let mac_buffer = &self.mac_buffer;
        #[cfg(feature = "zeroize")] 
        let mac_buffer = &self.mac_buffer[..self.mac_buffer_pos];

        self.mac.update_padded( mac_buffer );
        self.mac_buffer_pos = 0;
    }

    pub fn apply_associated_data( &mut self, associated_data: &[u8] ) -> Result<(), Error> {
        match self.mode {
            CipherMode::AfterNonce => {
                self.mode = CipherMode::AssociatedData;
            },
            CipherMode::AssociatedData => {},
            CipherMode::Data | CipherMode::Error => {
                self.mode = CipherMode::Error;
                return Err(Error);
            }
        }

        self.associated_data_length += associated_data.len() as u64;

        self.update_mac_buffer( associated_data );

        Ok(())
    }
}

impl<C> StreamCipher for Cipher<C>
where
    C: StreamCipher + StreamCipherSeek,
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
            CipherMode::AfterNonce => {
                self.mode = CipherMode::Data;
            },
            CipherMode::AssociatedData => {
                self.finalize_mac_buffer();
                self.mode = CipherMode::Data;
            },
            CipherMode::Data => {},
            CipherMode::Error => {
                return Err(StreamCipherError);
            }
        }

        self.data_length += buf.len() as u64;

        self.cipher.apply_keystream_inout( buf.reborrow() );
        self.update_mac_buffer( buf.get_out() );

        Ok(())
    }

}


