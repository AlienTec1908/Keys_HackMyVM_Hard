# Keys - HackMyVM (Hard)

![Keys.png](Keys.png)

## Übersicht

*   **VM:** Keys
*   **Plattform:**(https://hackmyvm.eu/machines/machine.php?vm=Keys)
*   **Schwierigkeit:** Hard
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 13. Oktober 2022
*   **Original-Writeup:** https://alientec1908.github.io/Keys_HackMyVM_Hard/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge war es, Root-Rechte auf der Maschine "Keys" zu erlangen. Der Weg dorthin umfasste die Ausnutzung einer Local File Inclusion (LFI)-Schwachstelle, um sensible Informationen wie Benutzer-Credentials und private Schlüssel zu exfiltrieren. Darauf folgten mehrere Privilege-Escalation-Schritte: Knacken von SSH-Schlüssel-Passphrasen, Ausnutzung einer fehlerhaften SUID-Konfiguration des `chsh`-Befehls, Ausnutzung einer unsicheren `sudo`-Regel in Verbindung mit einem Python-Skript und schließlich das Knacken einer PGP-Schlüssel-Passphrase, um das Root-Passwort zu erlangen.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `gobuster`
*   `curl`
*   `wget`
*   `base64`
*   `unzip`
*   `lftp`
*   `ssh`
*   `sudo`
*   `chsh`
*   `python3`
*   `rev`
*   `cp`
*   `chmod`
*   `vi` (oder `nano`)
*   `ssh2john`
*   `john`
*   `gpg2john`
*   `gpg`
*   `su`
*   `dcode.fr` (Web)
*   `8gwifi.org` (Web)
*   Standard Linux-Befehle (`ls`, `cat`, `find`, `grep`, etc.)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Keys" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Enumeration:**
    *   Identifizierung der Ziel-IP (192.168.2.147) mittels `arp-scan`.
    *   Portscan mit `nmap` offenbarte offene Ports: SSH (22/tcp, OpenSSH 8.4p1) und HTTP (80/tcp, Nginx 1.18.0, Titel "The World of Keys").

2.  **Web Enumeration & LFI Discovery:**
    *   Verzeichnis-Bruteforcing mit `gobuster` auf Port 80 fand u.a. `/id_rsa.zip` (ein großes Archiv mit SSH Public Keys) und `/readme.php`.
    *   Analyse von `readme.php` (mittels `curl` und manueller Base64-Dekodierung des Quellcodes aus einem Kommentar) enthüllte eine Local File Inclusion (LFI)-Schwachstelle im GET-Parameter `34sy`.

3.  **Initial Access (LFI -> `useless`):**
    *   Ausnutzung der LFI zum Lesen von `/etc/passwd` zur Identifizierung von Systembenutzern.
    *   Auslesen von `/etc/motd` via LFI (`http://192.168.2.147/readme.php?34sy=/etc/motd`) offenbarte Klartext-Credentials für den Benutzer `useless:user`.
    *   Erfolgreicher SSH-Login als `useless` mit den gefundenen Credentials.

4.  **Privilege Escalation (von `useless` zu `jack` via `rachel`'s Key):**
    *   Im Home-Verzeichnis von `useless` wurde der erste Teil der User-Flag (`youser.txt`) gefunden.
    *   Ein Hinweis in `/home/rachel/the/secret/file/is/in/etc/ssh/sshd_config.d/` führte zur Datei `/etc/ssh/sshd_config.d/.rachel_key.private`, die nur von `root:www-data` lesbar war.
    *   Exfiltration des verschlüsselten privaten DSA-Schlüssels von `rachel` mittels LFI als `www-data` (`http://192.168.2.147/readme.php?34sy=/etc/ssh/sshd_config.d/.rachel_key.private`).
    *   Der extrahierte Schlüssel war unvollständig (markiert mit `*` anstelle von `DSA` und mit fehlenden Zeichen). Nach Korrektur des Schlüsseltyps zu `DSA` wurde die Passphrase mit `ssh2john` und `john` (`rockyou.txt`) zu `jack4rachel` geknackt.
    *   SSH-Login als Benutzer `jack` mit dem privaten Schlüssel von Rachel und der geknackten Passphrase.

5.  **Privilege Escalation (von `jack` zu `rachel` via `chsh` SUID):**
    *   Im Home-Verzeichnis von `jack` wurde der zweite Teil der User-Flag (`usAr.txt`) gefunden.
    *   Die Suche nach SUID-Binaries (`find / -perm -4000`) zeigte, dass `/usr/bin/chsh` SUID-Root war und der Gruppe `jack` gehörte.
    *   Das Ausführen von `/usr/bin/chsh` als `jack` führte direkt zu einer Shell als Benutzer `rachel`.

6.  **Privilege Escalation (von `rachel` zu `steve` via `sudo` Python Skript):**
    *   Als `rachel` zeigte `sudo -l`, dass der Befehl `/usr/bin/python3 /opt/number_guessing_game.py` als Benutzer `steve` ohne Passwort ausgeführt werden konnte. (Dritter Teil der User-Flag in `/home/rachel/u$eR.txt` angenommen).
    *   Ausführung des Python-Skripts mit `sudo -u steve`. Das Skript bot an, bei Eingabe einer "4 digits Secret Number" Steves `id_rsa.pub` anzuzeigen.
    *   Die Eingabe von `4695` (eine Zahl, die im Kontext früherer SSH-Schlüsseldateinamen auftauchte) führte zur Ausgabe eines rückwärts geschriebenen SSH Public Keys (`root@targetcluster`).
    *   Nach Umkehrung des Strings (`rev`) wurde der korrekte Public Key sichtbar.
    *   Ein `grep` auf diesen Public Key in der zuvor heruntergeladenen Sammlung aus `id_rsa.zip` identifizierte den zugehörigen privaten Schlüssel (`a473e40621001f61dbf97b310b1caefb-4695`).
    *   SSH-Login als `steve` mit diesem privaten Schlüssel.

7.  **Privilege Escalation (von `steve` zu `root` via PGP):**
    *   Im Home-Verzeichnis von `steve` wurde der vierte Teil der User-Flag (`u__s__e__r.txt`) gefunden.
    *   Zusätzlich wurden die Dateien `.important_message.asc` (eine PGP-verschlüsselte Nachricht) und (in `/var/spool/mail/`) `private_key.gpg` (ein PGP Private Key, lesbar für `steve`) entdeckt.
    *   Die Passphrase des PGP Private Keys (`root@keys.com`) wurde mit `gpg2john` und `john` (`rockyou.txt`) zu `youdidit` geknackt.
    *   Die PGP-Nachricht wurde mit dem importierten privaten Schlüssel und der geknackten Passphrase entschlüsselt. Sie enthielt das Root-Passwort: `th3_h!dd3n_m3ss4g3`.
    *   Wechsel zum Root-Benutzer mit `su root` und dem gefundenen Passwort.

## Wichtige Schwachstellen und Konzepte

*   **Local File Inclusion (LFI):** Die Datei `/readme.php` enthielt eine LFI-Schwachstelle (`$_GET['34sy']`), die das Auslesen beliebiger Dateien wie `/etc/passwd`, `/etc/motd` und privater Schlüssel ermöglichte.
*   **Unsichere Speicherung von Zugangsdaten:** Klartext-Credentials (`useless:user`) wurden in `/etc/motd` gefunden. Das Root-Passwort wurde in einer PGP-Nachricht gespeichert, deren Schlüsselpassphrase geknackt werden konnte.
*   **Password Cracking (SSH & PGP Keys):** Erfolgreiches Knacken der Passphrasen für einen privaten DSA-Schlüssel (`jack4rachel`) und einen PGP Private Key (`youdidit`) mittels `ssh2john`/`gpg2john` und `john`.
*   **SUID-Fehlkonfiguration:** `/usr/bin/chsh` war SUID-Root und gehörte der Gruppe `jack`, was eine direkte Privilege Escalation von `jack` zu `rachel` ermöglichte.
*   **Unsichere `sudo`-Regel mit Informationspreisgabe:** `rachel` konnte ein Python-Skript als `steve` ausführen. Dieses Skript gab bei korrekter Eingabe einen SSH Public Key preis, was zu einem weiteren SSH-Zugang führte.
*   **Informationspreisgabe im Web-Root:** Sensible Dateien (`id_rsa.zip` mit Public Keys, LFI-anfällige `readme.php`) waren öffentlich über den Webserver zugänglich.

## Flags

*   **User Flag (`/home/useless/youser.txt, /home/jack/usAr.txt, /home/rachel/u$eR.txt, /home/steve/u__s__e__r.txt` - zusammengesetzt):** `4vJkfrYnYT7Q6PwVDll6`
*   **Root Flag (`/root/root.txt`):** `AeQgWYpsNcuL4BzXH2p1`

## Tags

`HackMyVM`, `Keys`, `Hard`, `LFI`, `SSH Key Cracking`, `SUID Exploit`, `PGP Key Cracking`, `Python Script Exploit`, `Linux`, `Web`, `Privilege Escalation`
