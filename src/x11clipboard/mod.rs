pub mod reader;
mod shared;
pub mod writer;

/*
TODO type groups to support?:
- utf8 text: text/plain;charset=utf-8, UTF8_STRING
- text: (utf8 types and) text/plain, TEXT, COMPOUND_TEXT, STRING
- image: (one of these, passthru) image/png, image/jpeg, image/webp

ACTUALLY I'm thinking we could have a ctrl+c involve the
*/
