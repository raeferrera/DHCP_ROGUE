<div align="center">

# 🕵️ DHCP Rogue / Spoofing Server

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?logo=python&logoColor=white)](https://python.org)
[![Scapy](https://img.shields.io/badge/Scapy-2.5+-00B050?logo=python)](https://scapy.net)
[![ITLA](https://img.shields.io/badge/ITLA-Cybersecurity-FF6B00)](https://www.itla.edu.do/)
[![License](https://img.shields.io/badge/License-Educational-red)](LICENSE)

**Raelina Ferrera · Matrícula: 2021-2371**  
*Seguridad en Redes — Instituto Tecnológico de las Américas*

</div>

---

## 📋 Tabla de Contenidos

- [Objetivo](#objetivo)
- [Topología](#topología)
- [Direccionamiento IP](#direccionamiento-ip)
- [Estructura del Repositorio](#estructura-del-repositorio)
- [Requisitos](#requisitos)
- [Instalación](#instalación)
- [Parámetros](#parámetros)
- [Uso](#uso)
- [Cómo Funciona](#cómo-funciona)
- [Capturas de Pantalla](#capturas-de-pantalla)
- [Medidas de Mitigación](#medidas-de-mitigación)
- [Advertencia Legal](#advertencia-legal)

---

## 🎯 Objetivo

El **DHCP Rogue / Spoofing Attack** consiste en desplegar un servidor DHCP falso dentro de la red que **responde más rápido** que el servidor legítimo. El servidor rogue entrega a las víctimas configuraciones de red maliciosas, principalmente un **gateway falso** (la IP del atacante), lo que permite interceptar todo el tráfico de la víctima (Man-in-the-Middle a nivel L3).

A diferencia del Starvation, este ataque **no busca denegar el servicio** sino redirigir silenciosamente el tráfico.

> **Flujo DHCP explotado:**  
> Víctima → DISCOVER (broadcast) → **[Rogue responde primero]** → OFFER → REQUEST → ACK (falso) → **Víctima usa gateway del atacante**

> **Marco de referencia:** MITRE ATT&CK — T1557 (Adversary-in-the-Middle)

---

## 🗺️ Topología

```
        ┌──────────┐
        │  INTERNET│
        │  (Cloud) │
        └────┬─────┘
             │ e0/0 (DHCP)
        ┌────┴─────┐
        │   R1     │  ← Servidor DHCP LEGÍTIMO
        │  Router  │     Gateway real: 10.21.23.1
        └────┬─────┘
             │ e0/1.23 (10.21.23.1/24)
             │ e0/0
        ┌────┴─────┐
        │   SW1    │  ← Switch VLAN 23 (sin DHCP Snooping)
        └──┬────┬──┘
      e0/2 │    │ e0/1
           │    │
    ┌──────┴──┐ ┌┴──────┐
    │  Linux  │ │  Win  │
    │ ROGUE   │ │Víctima│
    │ SERVER  │ │       │
    └─────────┘ └───────┘
  IP: 10.21.23.50   DHCP → recibe gateway FALSO 10.21.23.50
  (actúa como GW)
```

**Resultado del ataque:** La víctima cree que el atacante (10.21.23.50) es su gateway. Todo su tráfico pasa por el atacante antes de llegar a Internet.

---

## 📡 Direccionamiento IP

> **Base de matrícula:** 2021-**2371** → VLAN **23**, Subred **10.21.23.0/24**

| Dispositivo  | Interfaz      | IP               | Rol               |
|--------------|---------------|------------------|-------------------|
| R1           | e0/0          | DHCP (WAN)       | Router / DHCP legítimo |
| R1           | e0/1.23       | `10.21.23.1/24`  | Gateway real      |
| SW1          | e0/0          | Trunk → R1       | Uplink            |
| SW1          | e0/1          | Access → Win     | —                 |
| SW1          | e0/2          | Access → Linux   | —                 |
| Linux        | eth0          | `10.21.23.50/24` | **Atacante / Rogue DHCP** |
| Win          | eth0          | `10.21.23.100` (del rogue) | **Víctima** |

| Parámetro entregado por el Rogue | Valor legítimo | Valor **FALSO** |
|----------------------------------|----------------|-----------------|
| Gateway                          | `10.21.23.1`   | `10.21.23.50` ⚠️ |
| DNS                              | `8.8.8.8`      | `8.8.8.8`        |
| Pool de IPs                      | .51–.254       | .100–.199        |
| Lease time                       | 60s            | 3600s            |

---

## 📂 Estructura del Repositorio

```
DHCP_Rogue/
├── 📜 README.md
├── 📄 requirements.txt
├── 📄 .gitignore
│
├── 📂 scripts/
│   └── 🐍 dhcp_rogue.py              # Servidor DHCP Rogue principal
│
├── 📂 configs/
│   ├── 📄 R1_config.txt              # Config Router R1 (DHCP legítimo)
│   ├── 📄 SW1_config.txt             # Config Switch SW1
│   └── 🔧 setup_attacker.sh         # Setup máquina atacante
│
├── 📂 docs/
│   └── 📖 RaelinaFerrera_2021-2371_Informe_P2.pdf
│
└── 📂 evidencias/
    ├── 📂 capturas/                  # Archivos .pcap
    ├── 📂 screenshots/               # Capturas de pantalla
    └── 📂 videos/                    # Video demostración
```

---

## ⚙️ Requisitos

### Hardware / Virtualización

| Componente | Descripción |
|------------|-------------|
| Plataforma | GNS3 o PNETLab |
| Router     | Cisco IOL |
| Switch     | Cisco IOL Layer 2 (**sin DHCP Snooping** para el lab) |
| Atacante   | Linux (Kali / Ubuntu) |
| Víctima    | Windows (cualquier versión con DHCP activo) |

### Software

| Herramienta | Versión | Propósito |
|-------------|---------|-----------|
| Python      | ≥ 3.8   | Runtime   |
| Scapy       | ≥ 2.5.0 | Framework de ataque |
| Wireshark   | Cualquiera | Captura de evidencia |
| tcpdump     | Cualquiera | Captura en terminal |

---

## 🚀 Instalación

```bash
git clone https://github.com/raeferrera/DHCP_Rogue.git
cd DHCP_Rogue
pip install -r requirements.txt
bash configs/setup_attacker.sh
```

---

## 🔧 Parámetros

| Parámetro      | Largo           | Tipo   | Requerido | Default           | Descripción |
|----------------|-----------------|--------|-----------|-------------------|-------------|
| `-i`           | `--interface`   | string | ✅ SÍ     | —                 | Interfaz de red (ej. `eth0`) |
| `--rogue-ip`   | —               | string | ✅ SÍ     | —                 | IP del servidor rogue (IP del atacante) |
| `--fake-gw`    | —               | string | ❌ No     | IP del atacante   | Gateway FALSO a entregar a víctimas |
| `--fake-dns`   | —               | string | ❌ No     | `8.8.8.8`         | DNS a entregar a víctimas |
| `--pool-start` | —               | string | ❌ No     | `10.21.23.100`    | Primera IP del pool rogue |
| `--lease`      | —               | int    | ❌ No     | `3600`            | Lease time en segundos |

---

## 💻 Uso

### Iniciar servidor rogue (gateway = atacante)
```bash
sudo python3 scripts/dhcp_rogue.py -i eth0 --rogue-ip 10.21.23.50 --fake-gw 10.21.23.50
```

### Con DNS personalizado (ej. DNS propio para phishing)
```bash
sudo python3 scripts/dhcp_rogue.py -i eth0 --rogue-ip 10.21.23.50 \
    --fake-gw 10.21.23.50 --fake-dns 10.21.23.50
```

### Habilitar reenvío de tráfico (para que la víctima tenga Internet)
```bash
# El atacante actúa como router transparente
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

### Capturar tráfico interceptado
```bash
sudo tcpdump -i eth0 -w evidencias/capturas/rogue_mitm.pcap
```

---

## 🔬 Cómo Funciona

### Diagrama de intercambio DHCP

```
Víctima          Switch SW1           R1 (Legítimo)    Linux (Rogue)
   │                 │                      │                │
   │── DISCOVER ────►│──── BROADCAST ──────►│                │
   │                 │                      │                │
   │                 │──── BROADCAST ──────►│                │
   │                 │                      │                │
   │◄── OFFER ───────────────────────────────────────────────┤
   │    (gateway: 10.21.23.50) [LLEGA PRIMERO]               │
   │                 │                      │                │
   │   (OFFER del    │                      │                │
   │    legítimo     │◄─── OFFER ──────────┤                │
   │    ignorado)    │    gateway:10.21.23.1│                │
   │                 │                      │                │
   │── REQUEST ─────►│──── BROADCAST ──────►│──────────────►│
   │   (acepta rogue)│                      │                │
   │                 │                      │                │
   │◄── ACK ──────────────────────────────────────────────── │
   │  IP: 10.21.23.100 / GW: 10.21.23.50                    │
   │                 │                      │                │
   ▼  [Víctima configurada con gateway del atacante]         │
```

El servidor Rogue **responde más rápido** (sin procesamiento de base de datos) que el servidor legítimo, logrando que la víctima acepte su OFFER.

---

## 📸 Capturas de Pantalla

> Las capturas se encuentran en `evidencias/screenshots/`

| Evidencia | Descripción |
|-----------|-------------|
| `01_topologia.png` | Topología en GNS3/PNETLab |
| `02_rogue_iniciando.png` | Servidor rogue arrancado y esperando |
| `03_discover_recibido.png` | DISCOVER detectado de la víctima |
| `04_offer_ack_enviado.png` | OFFER y ACK rogue enviados |
| `05_victima_gateway_falso.png` | `ipconfig` en víctima mostrando gateway `10.21.23.50` |
| `06_wireshark_dhcp_flow.png` | Flujo completo DISCOVER→OFFER→REQUEST→ACK en Wireshark |
| `07_trafico_interceptado.png` | tcpdump mostrando tráfico de víctima |

---

## 🛡️ Medidas de Mitigación

### 1. DHCP Snooping (Principal — Cisco IOS)
```
SW1(config)# ip dhcp snooping
SW1(config)# ip dhcp snooping vlan 23
SW1(config)# no ip dhcp snooping information option
!
! Solo el puerto hacia el router legítimo es "trusted"
SW1(config)# interface Ethernet0/0
SW1(config-if)# ip dhcp snooping trust
!
! Puertos de acceso: "untrusted" (default) + rate limiting
SW1(config)# interface Ethernet0/2
SW1(config-if)# ip dhcp snooping limit rate 5
```
Con DHCP Snooping, cualquier DHCPOFFER o DHCPACK que llegue desde un puerto no confiable (como e0/2, donde está el atacante) es **descartado inmediatamente**.

### 2. Dynamic ARP Inspection (DAI)
Complementa DHCP Snooping validando que las IPs en paquetes ARP coincidan con la tabla de DHCP snooping binding.
```
SW1(config)# ip arp inspection vlan 23
SW1(config)# interface Ethernet0/0
SW1(config-if)# ip arp inspection trust
```

### 3. 802.1X — Autenticación de dispositivos
Solo dispositivos autenticados (usuarios/certificados) pueden participar en la red.

### 4. Monitoreo de red
Herramientas como Wireshark, SNORT o sistemas SIEM detectan múltiples servidores DHCP en la misma VLAN.

| Medida            | Efectividad | Complejidad |
|-------------------|-------------|-------------|
| DHCP Snooping     | ⭐⭐⭐⭐⭐ | Media       |
| DAI               | ⭐⭐⭐⭐   | Media       |
| 802.1X            | ⭐⭐⭐⭐⭐ | Alta        |
| Monitoreo SIEM    | ⭐⭐⭐     | Alta        |

---

## ⚠️ Advertencia Legal

```
╔══════════════════════════════════════════════════════════════╗
║  USO EXCLUSIVO PARA LABORATORIO EDUCATIVO — ITLA 2021-2371  ║
║                                                              ║
║  ❌ NO usar en redes de producción                          ║
║  ❌ NO usar sin autorización explícita del propietario      ║
║  ✅ Solo en entornos virtuales aislados (GNS3 / PNETLab)    ║
╚══════════════════════════════════════════════════════════════╝
```

---

<div align="center">

**Autor:** Raelina Ferrera  
**Matrícula:** 2021-2371  
**Institución:** Instituto Tecnológico de las Américas (ITLA)  
**Curso:** Seguridad en Redes  
**Fecha:** Febrero 2026

[![GitHub](https://img.shields.io/badge/GitHub-raeferrera-black?logo=github)](https://github.com/raeferrera)
[![ITLA](https://img.shields.io/badge/ITLA-Cybersecurity-orange)](https://www.itla.edu.do/)

</div>