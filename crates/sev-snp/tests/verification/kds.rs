use stogas_sev_snp::{ErrorKind, Product, Report, SigningKey, TcbVersion, kds};

use crate::fixtures::{case, unhex};

const GCP_CHIP: &str = "3e449e94094eaab2cfe4b44b27c9ae28cb56c196d85fe963c933a1cf1b8aff302956eee51582bf0a03038b821a42d533228865ba9ded2b9690ff7e195ddc888f";

fn chip(prefix: &str) -> [u8; 64] {
    let mut chip = [0; 64];
    let bytes = unhex(prefix);
    chip[..bytes.len()].copy_from_slice(&bytes);
    chip
}

const fn milan(bootloader: u8, tee: u8, snp: u8, microcode: u8) -> TcbVersion {
    TcbVersion {
        fmc: None,
        bootloader,
        tee,
        snp,
        microcode,
    }
}

#[test]
fn a_vcek_path_names_the_chip_and_the_reported_tcb() {
    let report = Report::parse(&case("gcp-milan-vmpl0").inputs().report).unwrap();
    assert_eq!(
        kds::vcek_path(Product::Milan, report.chip_id(), report.reported_tcb()).unwrap(),
        format!("/vcek/v1/Milan/{GCP_CHIP}?blSPL=4&teeSPL=0&snpSPL=31&ucodeSPL=225")
    );
    // The chip and SPLs of the Turin VCEK in the virtee fixtures.
    let turin = TcbVersion {
        fmc: Some(0),
        ..milan(0, 0, 0, 9)
    };
    assert_eq!(
        kds::vcek_path(Product::Turin, &chip("1e550a8ee5cf9f4d"), turin).unwrap(),
        "/vcek/v1/Turin/1e550a8ee5cf9f4d?fmcSPL=0&blSPL=0&teeSPL=0&snpSPL=0&ucodeSPL=9"
    );
}

#[test]
fn a_vcek_path_needs_a_chip_id_and_spls_that_kds_accepts() {
    let gcp = chip(GCP_CHIP);
    let tcb = milan(4, 0, 31, 225);
    let turin = TcbVersion {
        fmc: Some(1),
        ..tcb
    };
    for (product, chip_id, tcb) in [
        // AWS masks the chip ID.
        (Product::Milan, [0; 64], tcb),
        // A Turin chip ID uses only its first 8 bytes.
        (Product::Turin, gcp, turin),
        (Product::Turin, [0; 64], turin),
        (Product::Milan, gcp, turin),
        (Product::Turin, chip("1e550a8ee5cf9f4d"), tcb),
        (Product::Milan, gcp, milan(128, 0, 31, 225)),
        (Product::Milan, gcp, milan(4, 128, 31, 225)),
        (Product::Genoa, gcp, milan(4, 0, 128, 225)),
        (
            Product::Turin,
            chip("1e550a8ee5cf9f4d"),
            TcbVersion {
                fmc: Some(128),
                ..tcb
            },
        ),
    ] {
        assert_eq!(
            kds::vcek_path(product, &chip_id, tcb).unwrap_err().kind(),
            ErrorKind::Report,
            "{product} {tcb:?}"
        );
    }
    assert_eq!(
        kds::vcek_path(Product::Genoa, &gcp, milan(127, 127, 127, 255)).unwrap(),
        format!("/vcek/v1/Genoa/{GCP_CHIP}?blSPL=127&teeSPL=127&snpSPL=127&ucodeSPL=255")
    );
}

#[test]
fn kds_serves_chains_and_crls_by_product() {
    assert_eq!(kds::ORIGIN, "https://kdsintf.amd.com");
    assert_eq!(
        kds::certificate_chain_path(Product::Milan, SigningKey::Vcek).unwrap(),
        "/vcek/v1/Milan/cert_chain"
    );
    assert_eq!(
        kds::certificate_chain_path(Product::Genoa, SigningKey::Vlek).unwrap(),
        "/vlek/v1/Genoa/cert_chain"
    );
    assert_eq!(
        kds::certificate_chain_path(Product::Turin, SigningKey::None)
            .unwrap_err()
            .kind(),
        ErrorKind::Unsigned
    );
    assert_eq!(kds::crl_path(Product::Turin), "/vcek/v1/Turin/crl");
}
