# win-acl-rs

A simple and safe abstraction over Windows ACLs (Access Control Lists) and security descriptors.

[![github actions](https://github.com/sramekj/win-acl-rs/workflows/CI/badge.svg)](https://github.com/sramekj/win-acl-rs/actions)
[![License](https://img.shields.io/badge/license-Apache--2.0_OR_MIT-blue.svg)](https://github.com/sramekj/win-acl-rs)

## Features

- Create and manipulate ACLs and ACEs (Access Control Entries)
- Work with security descriptors (SDs)
- Handle SIDs (Security Identifiers) and well-known security principals
- Query and modify file, registry, service, and other object permissions
- Support both standard and elevated privilege operations

## Examples

### Working with SIDs

```rust
use win_acl_rs::{sid::Sid, wellknown::WinBuiltinAdministratorsSid};

// Create a SID from a well-known constant (recommended)
let admin_sid = Sid::from_well_known_sid(WinBuiltinAdministratorsSid)?;

// Or create from string representation
let everyone_sid = Sid::from_string("S-1-1-0")?; // Everyone SID

// Look up account information
let lookup = admin_sid.lookup_name()?;
println!("Account: {}\\{}", lookup.domain, lookup.name);

// Convert to string
let sid_string = admin_sid.to_string()?;
println!("SID: {}", sid_string);
```

### Creating and Manipulating ACLs

```rust
use win_acl_rs::{acl::Acl, mask::AccessMask, sid::Sid};
use win_acl_rs::wellknown::{WinWorldSid, WinBuiltinAdministratorsSid};

// Create a new ACL
let mut acl = Acl::new()?;

// Add an access-allowed ACE using well-known SID
let everyone_sid = Sid::from_well_known_sid(WinWorldSid)?;
acl.allow(AccessMask::full().as_u32(), &everyone_sid)?;

// Add read-only access for Administrators
let admin_sid = Sid::from_well_known_sid(WinBuiltinAdministratorsSid)?;
acl.allow(AccessMask::read().as_u32(), &admin_sid)?;

// Iterate over ACEs
for ace in &acl {
    let sid = ace.sid()?;
    let account = sid.lookup_name().ok();
    println!(
        "ACE: {:?}, Account: {:?}, Mask: 0x{:X}",
        ace.ace_type(),
        account.map(|a| format!("{}\\{}", a.domain, a.name)),
        ace.mask()
    );
}
```

### Reading Security Descriptors from Files

```rust
use win_acl_rs::sd::SecurityDescriptor;

// Read security descriptor from a file
let sd = SecurityDescriptor::from_path("C:\\path\\to\\file.txt")?;

// Get the owner SID
if let Some(owner) = sd.owner_sid() {
    println!("Owner SID: {}", owner.to_string()?);
    // Look up account name (requires unsafe as we're using raw pointers)
    unsafe {
        if let Ok(lookup) = owner.lookup_name() {
            println!("Owner account: {}\\{}", lookup.domain, lookup.name);
        }
    }
}

// Iterate over DACL entries
if let Some(dacl) = sd.dacl() {
    println!("DACL contains {} ACEs", dacl.ace_count());
    for ace in &dacl {
        if let Ok(sid) = ace.sid() {
            println!("ACE: {:?} for SID: {}", ace.ace_type(), sid);
        }
    }
}
```

### Using Different Access Masks

```rust
use win_acl_rs::mask::{AccessMask, FileAccess, RegistryAccess};

// Generic access masks (work across object types)
let read_mask = AccessMask::read();      // GENERIC_READ | READ_CONTROL
let write_mask = AccessMask::write();    // GENERIC_WRITE | WRITE_DAC
let full_mask = AccessMask::full();      // GENERIC_ALL

// File-specific access masks
let file_read = FileAccess::READ;
let file_write = FileAccess::WRITE;

// Registry-specific access masks
let reg_query = RegistryAccess::QUERY;
let reg_full = RegistryAccess::FULL;
```

### Working with Different Object Types

```rust
use win_acl_rs::sd::SecurityDescriptor;
use win_acl_rs::SE_REGISTRY_KEY;

// Read security descriptor from a registry key
let sd = SecurityDescriptor::from_handle(
    "MACHINE\\SOFTWARE\\MyKey",
    SE_REGISTRY_KEY
)?;

// Check if DACL is present
if sd.dacl_present()? {
    println!("DACL is present");
}
```

### Elevated Privileges for SACL Access

```rust
use win_acl_rs::elevated::{PrivilegeToken, SecurityDescriptorElevated};

// Check if running as administrator
if win_acl_rs::elevated::is_admin()? {
    // Try to elevate privileges to access SACLs
    let token = PrivilegeToken::new();
    if let Ok(elevated_token) = token.try_elevate() {
        // Now can read SACL (System Access Control List)
        let sd = SecurityDescriptorElevated::from_path(
            &elevated_token,
            "C:\\path\\to\\file.txt"
        )?;
        
        // Access SACL information
        if sd.sacl_present()? {
            println!("SACL is present (auditing enabled)");
        }
    }
}
```

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
win-acl-rs = "0.1"
```

**Note:** This crate is Windows-only and will not compile on other platforms.


## License

Licensed under either of

* Apache License, Version 2.0
  ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license
  ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.