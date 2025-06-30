use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Public values for the prover.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZKMPublicValues {
    buffer: Buffer,
}

impl ZKMPublicValues {
    /// Create a new `ZKMPublicValues`.
    pub const fn new() -> Self {
        Self { buffer: Buffer::new() }
    }

    /// Create a `ZKMPublicValues` from a slice of bytes.
    pub fn from(data: &[u8]) -> Self {
        Self { buffer: Buffer::from(data) }
    }

    /// Read a value from the buffer.
    pub fn read<T: Serialize + DeserializeOwned>(&mut self) -> T {
        self.buffer.read()
    }
}

/// A buffer of serializable/deserializable objects.                                              
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Buffer {
    pub data: Vec<u8>,
    #[serde(skip)]
    pub ptr: usize,
}

impl Buffer {
    pub const fn new() -> Self {
        Self { data: Vec::new(), ptr: 0 }
    }

    pub fn from(data: &[u8]) -> Self {
        Self { data: data.to_vec(), ptr: 0 }
    }

    /// Read the serializable object from the buffer.                                             
    pub fn read<T: Serialize + DeserializeOwned>(&mut self) -> T {
        let result: T =
            bincode::deserialize(&self.data[self.ptr..]).expect("failed to deserialize");
        let nb_bytes = bincode::serialized_size(&result).expect("failed to get serialized size");
        self.ptr += nb_bytes as usize;
        result
    }
}
