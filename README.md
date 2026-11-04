# DokuVault Scanner für Windows

Scannt das lokale Netzwerk, erkennt, was für Geräte dort hängen, und legt die ausgewählten in
[DokuVault](https://github.com/PhilippKuhlmann/dokuvault) an – samt IP-Adresse, VLAN und MAC.

Angeboten werden alle DokuVault-Typen mit IP-Adressen. Sichtbar ist jeweils nur, was der Benutzer beim
gewählten Kunden anlegen darf.

| Bereich | Typen |
|---|---|
| Netzwerk | Router, Firewall, Switch, Accesspoint |
| Server & Speicher | Server, VM, NAS, USV |
| Clients | Computer, Sonstiger Client, Drucker, Scanner, IoT-Gerät, Maschine |
| Telefonie | Telefon, TK-Anlage, DECT |
| Kamera | Kamera, Recorder |

Die Formulare kommen vom Server. Ein Typ wird beim ersten Gebrauch geladen; die Felder und Pflichtangaben
sind also immer die der DokuVault-Installation.

Die App nutzt dieselbe Schnittstelle wie die iOS-App (`/api/mobile`, siehe `docs/mobile-api.md` im
DokuVault-Repository). Sie hat dieselben Rechte wie der Benutzer im Browser. Am Server muss dafür nichts
geändert werden.

## Ablauf

1. **Anmelden** mit Serveradresse, Benutzername und Kennwort. Ist eine zweite Stufe eingerichtet, folgt
   der Code aus der Authenticator-App oder ein Wiederherstellungscode.
   - Gespeichert wird nur das Token (30 Tage gültig), verschlüsselt per DPAPI für das Windows-Konto.
   - Das Kennwort wird nie gespeichert.
2. **Kunde wählen.** Die App lädt:
   - die Formulare für *IoT-Gerät* und *Drucker*,
   - die Standorte,
   - die VLANs mit ihren IP-Plänen. Daraus ergibt sich, welche Adressen schon dokumentiert sind.
3. **Netzwerk scannen.** Vorgeschlagen wird das Netz dieses Rechners. Möglich sind auch ein CIDR, eine
   Spanne (`192.168.1.10-80`) oder eine einzelne Adresse, höchstens /20.
4. **Prüfen und auswählen.** Je Gerät zeigt die Liste Name, Hersteller, Modell, MAC, Dienste und den
   vorgeschlagenen Typ, z. B. *Kamera*, *Accesspoint* oder *USV*. Unter „Übernehmen als“ wird der Typ
   festgelegt. Rechts stehen:
   - die Felder des DokuVault-Formulars, vorbelegt aus dem Scan,
   - das VLAN,
   - die Bezeichnung der Adresse (die MAC),
   - alles, was das Gerät über sich verraten hat.
5. **Übernehmen.** Die App legt jedes gewählte Gerät an und hängt die IP-Adresse an.
   - Ist die Adresse beim Kunden schon vergeben, nimmt sie das neue Gerät wieder zurück (Papierkorb),
     damit kein Duplikat entsteht.

## DHCP-Bereich

Das Feld „DHCP-Bereich“ neben dem Scan-Bereich belegt die App aus dem VLAN vor, das zum Scan-Bereich passt
(`dhcpStart`/`dhcpEnd` in DokuVault, bei zwei Standorten mit demselben Netz der des gewählten Standorts). Es lässt
sich überschreiben: `192.168.1.100-199`, mehrere Bereiche mit Komma. Die Eingabe merkt sich die App je Kunde und
Scan-Bereich; leert man das Feld, gilt beim nächsten Laden wieder der Wert aus dem VLAN.

Geräte darin bekommen in der Liste einen Randstrich, eine getönte Zeile und die Marke „DHCP“, in den Farben des
IP-Plans der Weboberfläche. Das Feld selbst ändert nichts am VLAN in DokuVault.

Geräte darin legt die App **per DHCP** an: ohne Adresse, nur mit VLAN und Bezeichnung. Rechts lässt sich das je Gerät
abwählen, zum Beispiel für eine feste Adresse mitten im Pool. Per DHCP braucht DokuVault immer ein VLAN.

Weil dann keine Adresse gespeichert ist, greift die Sperre „Adresse schon vergeben“ nicht. Die App schreibt deshalb die
MAC in die Bezeichnung und erkennt das Gerät daran wieder. Dafür ruft sie beim Laden eines Kunden jedes per DHCP
dokumentierte Gerät einmal ab. Ein Gerät ohne feste MAC (zufällige MAC, anderes Subnetz) erkennt sie später nicht.

## Darstellung

Hell, dunkel oder „wie Windows“. Die letzte Einstellung folgt dem App-Modus von Windows, auch während die App
läuft. Umgeschaltet wird über das Symbol oben rechts (Monitor → Sonne → Mond) oder mit `Strg+Umschalt+D`
direkt zwischen hell und dunkel. Die Farben sind die der DokuVault-Weboberfläche samt ihrem Dark Mode, und
auch die Titelleiste wird dunkel.

Die Farben stehen in `Themes/Light.xaml` und `Themes/Dark.xaml`, die Vorlagen der Steuerelemente in
`Themes/Controls.xaml`.

## Was der Scan liest

| Quelle | Wofür |
|---|---|
| Ping + ARP-Cache (GetIpNetTable2), SendARP | Wer da ist, auch hinter einer Firewall; MAC-Adresse |
| IEEE-Herstellerlisten (MA-L, MA-M, MA-S) | Hersteller aus der MAC. Einmal geladen, nach 90 Tagen erneuert |
| TCP-Ports (9100, 631, 515, 1883, 8009, 554, 80, 443, 445, 3389 …) | Druck-, IoT-, Kamera- und PC-Dienste |
| SNMP v2c/v1 (Community einstellbar) | Druckermodell, Seriennummer, sysDescr |
| mDNS / DNS-SD | IPP, HomeKit, Matter, Chromecast, Shelly, ESPHome, Hue, Sonos … samt TXT-Angaben |
| SSDP / UPnP | Name, Hersteller, Modell und Seriennummer aus der Gerätebeschreibung |
| Reverse-DNS, NetBIOS | Rechnernamen |
| HTTP(S)-Startseite | Titel der Weboberfläche, URL für IoT-Geräte |

Der Vorschlag ist eine Bewertung aus diesen Merkmalen. Die Gründe stehen beim Gerät, entscheiden muss der
Benutzer.

Die Ports und die Erkennung stehen in `src/DokuVault.Scanner.Core/Scanning/DeviceClassifier.cs`.

## Bauen

Voraussetzung ist das .NET 10 SDK.

```bash
dotnet test
```

```bash
dotnet run --project src/DokuVault.Scanner
```

Eine einzelne EXE zum Weitergeben (enthält die .NET-Laufzeit):

```bash
dotnet publish src/DokuVault.Scanner -c Release -r win-x64 --self-contained -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true -o publish
```

Ergebnis: `publish/DokuVaultScanner.exe`.

## Neue Version veröffentlichen

GitHub baut die EXE selbst (`.github/workflows/release.yml`). Dafür reicht ein Tag:

```bash
git tag v1.1.0
```

```bash
git push origin v1.1.0
```

Der Workflow läuft auf einem Windows-Runner und erledigt den Rest:

1. Er testet den Stand.
2. Er baut die EXE mit der Version aus dem Tag.
3. Er erstellt das Release „DokuVault Scanner 1.1.0“ mit `DokuVaultScanner.exe`, der SHA-256-Datei und den Änderungen seit dem letzten Tag.

Von Hand unter *Actions → Release → Run workflow* gestartet, ist es ein Probelauf: Der Workflow testet und baut nur, die
EXE liegt dann sieben Tage als Artefakt beim Lauf, und es entsteht kein Release.

Jeder Push auf `main` und jeder Pull Request lässt außerdem die Tests laufen (`.github/workflows/ci.yml`).

## Daten auf dem Rechner

Alles liegt in `%LOCALAPPDATA%\DokuVault Scanner`:

- `settings.json`: Server, Benutzername, letzter Kunde, Standort, Bereich
- `token.bin`: das Token, per DPAPI verschlüsselt
- `oui.csv`, `mam.csv`, `oui36.csv`: die Herstellerlisten

„Abmelden“ widerruft das Token am Server und löscht es hier.

## Aufbau

```
src/DokuVault.Scanner.Core   Scan (Scanning/) und DokuVault-Client (Api/), ohne Oberfläche
src/DokuVault.Scanner        WPF-Oberfläche (MVVM)
tests/DokuVault.Scanner.Tests
```

## Grenzen

- DokuVault hat kein MAC-Feld. Die MAC steht deshalb in der Bezeichnung der IP-Adresse.
- Hersteller und MAC gibt es nur im eigenen Subnetz. Hinter einem Router antwortet ARP nicht.
- Ohne das Recht auf VLANs (`network_viewAny`) prüft die App jede Adresse vor dem Anlegen einzeln über die
  Suche. Die Prüfung beim Anhängen der IP hat in jedem Fall das letzte Wort.
