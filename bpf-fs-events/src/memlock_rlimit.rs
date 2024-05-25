pub fn get_memlock_rlimit() -> Result<libc::rlimit, Box<dyn std::error::Error>> {
    let mut rlimit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut rlimit) } != 0 {
        Err(Box::new(std::io::Error::last_os_error()))?;
    }
    Ok(rlimit)
}

pub fn set_memlock_rlimit(rlimit: libc::rlimit) -> Result<(), Box<dyn std::error::Error>> {
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        Err(Box::new(std::io::Error::last_os_error()))?;
    }
    Ok(())
}

pub fn bump_memlock_rlimit() -> Result<(), Box<dyn std::error::Error>> {
    const WANT_RLIMIT: libc::rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };
    let cur = get_memlock_rlimit()?;
    if cur.rlim_cur < WANT_RLIMIT.rlim_cur {
        set_memlock_rlimit(WANT_RLIMIT)?;
    }
    Ok(())
}
