pub mod reader;
mod shared;
pub mod writer;

pub struct ClipboardData {
    /// The type that this data is associated with
    pub type_: String,

    /// The retrieved data
    pub data: Vec<u8>,

    /// Zero once the data is retrieved
    pub remaining_bytes: usize,
}
