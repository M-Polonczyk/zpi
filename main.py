from src.pfsense import (
    fetch_pfsense_config,
    push_pfsense_config,
    load_pfsense_config_from_file,
)

from src.generate_config import wygeneruj_zmiane_konfiguracji

def main():
    # Load from example file
    # config = load_pfsense_config_from_file("example_config.xml")

    # Load from pfSense device
    # config = fetch_pfsense_config()

    # print(f"{config.dhcpd.lan.range=}")
    # config.dhcpd.lan.range.from_ = "192.168.1.10"
    # config.dhcpd.lan.range.to = "192.168.1.120"
    # print(f"{config.dhcpd.lan.range=}")

    # push_pfsense_config(config=config)
    
    opis = "Change the DHCP range on the LAN interface from 192.168.1.10 to 192.168.1.20"
    zmiana = wygeneruj_zmiane_konfiguracji(opis)
    if zmiana:
        print("✅ Wygenerowana zmiana:")
        print(zmiana)
    else:
        print("❌ Nie udało się wygenerować konfiguracji.")


if __name__ == "__main__":
    main()
