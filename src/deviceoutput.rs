pub const VIRTUAL_DEVICE_NAME_PREFIX: &str = "nikau virtual";

pub const ABS_MAX: libc::c_int = 0x3f;
pub const ABS_CNT: libc::c_int = ABS_MAX + 1;

pub const UINPUT_MAX_NAME_SIZE: libc::c_int = 80;
pub const UINPUT_VERSION: libc::c_int = 5;

pub struct input_id {
    pub bustype: u16,
    pub vendor: u16,
    pub product: u16,
    pub version: u16,
}

pub struct uinput_setup {
    pub id: input_id,
    pub name: [libc::c_char; 80],
    pub ff_effects_max: u32,
}

pub struct uinput_user_dev {
    pub name: [libc::c_char; 80],
    pub id: input_id,
    pub ff_effects_max: u32,
    pub absmax: [i32; 64],
    pub absmin: [i32; 64],
    pub absfuzz: [i32; 64],
    pub absflat: [i32; 64],
}
