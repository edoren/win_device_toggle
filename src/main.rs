use anyhow::{anyhow, Result};
use clap::Parser;
use log::info;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{prelude::*, EnvFilter, Layer};
use windows::Win32::{
    Devices::{
        DeviceAndDriverInstallation::{
            SetupDiChangeState, SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo,
            SetupDiGetClassDevsW, SetupDiGetDevicePropertyW, SetupDiSetClassInstallParamsW,
            DICS_DISABLE, DICS_ENABLE, DICS_FLAG_GLOBAL, DIF_PROPERTYCHANGE, DIGCF_ALLCLASSES,
            DIGCF_PRESENT, HDEVINFO, SP_CLASSINSTALL_HEADER, SP_DEVINFO_DATA, SP_PROPCHANGE_PARAMS,
        },
        Properties::{
            DEVPKEY_Device_FriendlyName, DEVPKEY_Device_HardwareIds, DEVPKEY_Device_InstanceId,
            DEVPROPKEY, DEVPROPTYPE,
        },
    },
    Foundation::{GetLastError, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS},
};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    /// Devices to enable
    #[arg(short, long, num_args = 1.., value_name = "DEVICE")]
    enable: Vec<String>,

    /// Devices to disable
    #[arg(short, long, num_args = 1.., value_name = "DEVICE")]
    disable: Vec<String>,

    /// Use device instance id instead of hardware id
    #[arg(long, action = clap::ArgAction::SetTrue)]
    use_device_instance: bool,
}

unsafe fn get_device_property(
    dev_info: HDEVINFO,
    dev_data: SP_DEVINFO_DATA,
    property: &DEVPROPKEY,
) -> Result<Vec<String>> {
    let mut dev_proptype = DEVPROPTYPE::default();
    let mut dw_buffersize = 0;

    let result = SetupDiGetDevicePropertyW(
        dev_info,
        &dev_data,
        property,
        &mut dev_proptype,
        None,
        Some(&mut dw_buffersize),
        0,
    );

    if result.is_err() && GetLastError() != ERROR_INSUFFICIENT_BUFFER {
        result?;
    }

    let mut dev_buffer = vec![0 as u8; dw_buffersize as usize];
    SetupDiGetDevicePropertyW(
        dev_info,
        &dev_data,
        property,
        &mut dev_proptype,
        Some(dev_buffer.as_mut_slice()),
        None,
        0,
    )?;

    let value_raw: Vec<u16> = dev_buffer
        .chunks_exact(2)
        .into_iter()
        .map(|a| u16::from_ne_bytes([a[0], a[1]]))
        .collect();
    let value_raw = value_raw.as_slice();

    let mut result = Vec::new();
    for it in value_raw.split(|val| *val == 0x00) {
        if it.len() > 0 {
            result.push(String::from_utf16_lossy(it));
        }
    }
    Ok(result)
}

fn set_device_state(device_name: String, enabled: bool, use_device_instance: bool) -> Result<()> {
    unsafe {
        if let Ok(dev_info) =
            SetupDiGetClassDevsW(None, None, None, DIGCF_ALLCLASSES | DIGCF_PRESENT)
        {
            let mut dev_count = 0;
            loop {
                let mut dev_data = SP_DEVINFO_DATA::default();
                dev_data.cbSize = std::mem::size_of::<SP_DEVINFO_DATA>() as u32;

                let result = SetupDiEnumDeviceInfo(dev_info, dev_count, &mut dev_data);
                if result.is_err() && GetLastError() == ERROR_NO_MORE_ITEMS {
                    break;
                };

                let friendy_name =
                    get_device_property(dev_info, dev_data, &DEVPKEY_Device_FriendlyName)
                        .unwrap_or_default()
                        .first()
                        .cloned()
                        .unwrap_or("Unknown-Name".into());

                let property = if use_device_instance {
                    DEVPKEY_Device_InstanceId
                } else {
                    DEVPKEY_Device_HardwareIds
                };

                let identifier =
                    get_device_property(dev_info, dev_data, &property).unwrap_or_default();

                if identifier.contains(&device_name) {
                    info!(
                        "Device with name '{friendy_name}' {}",
                        if enabled { "enabled" } else { "disabled" }
                    );

                    let mut pc_params = SP_PROPCHANGE_PARAMS {
                        ClassInstallHeader: SP_CLASSINSTALL_HEADER {
                            cbSize: std::mem::size_of::<SP_CLASSINSTALL_HEADER>() as _,
                            InstallFunction: DIF_PROPERTYCHANGE,
                        },
                        StateChange: if enabled { DICS_ENABLE } else { DICS_DISABLE },
                        Scope: DICS_FLAG_GLOBAL,
                        HwProfile: 0,
                    };

                    SetupDiSetClassInstallParamsW(
                        dev_info,
                        Some(&dev_data),
                        Some(&mut pc_params.ClassInstallHeader),
                        std::mem::size_of::<SP_PROPCHANGE_PARAMS>() as u32,
                    )
                    .map_err(|e| anyhow!("Could not change parameters: {e}"))?;

                    SetupDiChangeState(dev_info, &mut dev_data)
                        .map_err(|e| anyhow!("Could not change state: {e}"))?;

                    return Ok(());
                }

                dev_count += 1;
            }

            SetupDiDestroyDeviceInfoList(dev_info)?;
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Logging

    let default_filter = |filter: LevelFilter| {
        EnvFilter::builder()
            .with_default_directive(filter.into())
            .from_env_lossy()
    };

    let stdout_layer = tracing_subscriber::fmt::layer()
        .with_filter(default_filter(LevelFilter::INFO))
        .boxed();

    let layers = vec![stdout_layer];

    tracing_subscriber::registry().with(layers).init();

    // App

    for device in args.enable {
        set_device_state(device.clone(), true, args.use_device_instance)?;
    }

    for device in args.disable {
        set_device_state(device.clone(), false, args.use_device_instance)?;
    }

    Ok(())
}
