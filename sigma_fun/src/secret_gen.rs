

pub trait Transcript {
    pub fn add_name(&mut self, name: &str) -> Self;
    pub fn write_statement()
}


pub trait SecretGen  {
    fn new_secret<L: ArrayLength<u8>> -> [u8;64];
}
