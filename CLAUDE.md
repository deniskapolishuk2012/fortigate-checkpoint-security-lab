# FortiGate Security Lab — Мидл+ портфолио проект

## Цель проекта
Демонстрация навыков сетевой безопасности для собеседований: FortiGate (HQ firewall), Check Point R81.20 (Branch firewall), BGP/OSPF маршрутизация, WAF, IPS, Site-to-Site VPN, SIEM pipeline.

Лаба развёрнута в Eve-NG (192.168.120.135) на VMware.

---

## Сетевая топология

| Устройство | IP | Зона |
|------------|-----|------|
| FortiGate port1 | 192.168.10.1/24 | Users GW |
| FortiGate port2 | 192.168.20.1/24 | Servers GW / линк к frr-router |
| FortiGate port3 (WAN/mgmt) | 192.168.120.200/24 | VMware NAT |
| VPC1 (VPCS) | 192.168.10.10/24 | Users |
| frr-router (Ubuntu 22.04) | 192.168.20.20/24 | Linux BGP/OSPF router |
| Check Point cp-branch-gw eth0 (WAN) | 192.168.120.201/24 | VMware NAT (internet) |
| Check Point cp-branch-gw eth1 (LAN) | 192.168.40.1/24 | branch-lan сегмент |
| Check Point cp-branch-gw eth2 (DMZ) | 192.168.30.1/24 | branch-dmz сегмент |
| Wazuh SIEM | 192.168.120.134/24 | VMware NAT |
| Attacker VM | 192.168.120.130/24 | VMware NAT |
| Eve-NG | 192.168.120.135 | VMware NAT |

## Доступы / Credentials

| Сервис | Адрес | Логин | Пароль |
|--------|-------|-------|--------|
| Eve-NG WebUI | http://192.168.120.135 | admin | eve |
| FortiGate GUI/SSH | https://192.168.120.200 | admin | Admin123456! |
| Attacker VM SSH | 192.168.120.130 | labadmin | Aa12345678 |
| frr-router SSH | через FortiGate jump: `execute ssh labadmin@192.168.20.20` | labadmin | Aa12345678 |
| Check Point SSH/clish | 192.168.120.201 | admin | Aa1234 |
| Check Point Expert mode | (после `expert` в clish) | — | Aa1234 |
| Check Point SmartConsole | 192.168.120.201 | admin | Aa1234 |
| Check Point WebUI (Gaia Portal) | https://192.168.120.201 | admin | Aa1234 |
| Wazuh Dashboard | https://192.168.120.134 | admin | *ilO?4TXERTbCE2kMHMHDN6RL0R7rkhN |

---

## Статус блоков

### ✅ Блок 1 — Microsoft Sentinel (завершён 2026-06-07)
- FortiGate → Wazuh → Sentinel pipeline настроен
- Analytics Rule "FortiGate - Repeated Admin Login Failures" (MITRE T1110, severity Medium)
- Атака: sshpass + bash-цикл → 64 failed attempts → 15 инцидентов в Sentinel
- **Грабли:** Hydra v9.6 несовместима с SSH FortiGate v8.0 → решение через sshpass + OpenSSH
- Скриншоты: есть в папке screenshots/

### ✅ Блок 2 — DNAT + WAF + SQLi-атака (завершён 2026-06-07)
- VIP "VIP-WebServer-SQLi": 192.168.120.200:8080 → 192.168.120.129:80 (backend Linux target из Linux Security Lab)
- Hairpin/intra-interface policy port3→port3, inspection-mode proxy, waf-profile default
- SQLi-атака → HTTP 403 WAF block → Wazuh rule 81620 → Sentinel (полная цепочка подтверждена)
- **Грабли:** WAF требует proxy inspection-mode (не flow-based); UFW порядок правил критичен; trial лицензия ограничивает до 3 policies
- Скриншоты: есть в папке screenshots/

### ✅ Блок 3 — BGP/OSPF маршрутизация (завершён 2026-06-08)
- OSPF area 0: FortiGate (192.168.20.1) ↔ frr-router (192.168.20.20), Full/DR ↔ Full/Backup
- eBGP: AS 65001 (FortiGate) ↔ AS 65002 (frr-router), маршрут 172.16.0.0/24 появился на FortiGate
- **Грабли:** FortiGate OSPF router-id был 0.0.0.0 → "Process is not up" → исправлено `set router-id 192.168.20.1`
- **Грабли:** FRR 8.x `bgp ebgp-requires-policy` блокирует route exchange без явных policy → `no bgp ebgp-requires-policy`
- Скриншоты: есть в папке screenshots/

### 🔄 Блок 4 — Check Point firewall + VPN (в работе)

#### ✅ 4.1 Deploy + SmartConsole (завершён 2026-06-07)
- VM: QEMU cpsg-r8120 в Eve-NG, Check Point R81.20 build 634, Open Server
- FTCW пройден: hostname `cp-branch-gw`, Standalone (Security Gateway + Management)
- Интерфейсы настроены через clish, подключены в Eve-NG топологии:
  - eth0 → internet cloud (WAN, External)
  - eth1 → branch-lan (Internal, 192.168.40.0/24)
  - eth2 → branch-dmz (Internal + DMZ, 192.168.30.0/24)
- SmartConsole подключён, Topology настроена (External/Internal/DMZ), Anti-Spoofing Prevent/Log на всех
- **Грабли:** Gaia инсталлятор требует VNC-консоль в Eve-NG (не telnet — зависает на iPXE)
- **Грабли:** IP 192.168.20.0/24 занят Block 3 (OSPF/BGP), пришлось взять 192.168.40.0/24 для Branch-LAN
- **Грабли:** SmartConsole кэширует интерфейсы → после изменений через clish жать "Get Interfaces.."

#### ⏳ Осталось в Блоке 4:
- [x] 4.2 Object Management: Network objects, Host objects, Groups, Service objects
- [x] 4.3 Security Policy: Stealth rule, VPN traffic, Branch LAN out, DMZ Web, Cleanup + Application Control (блок P2P/torrent)
- [x] 4.4 NAT Rules: Hide NAT для Branch-LAN, Static NAT для DMZ веб-сервера
- [ ] 4.5 IPsec Site-to-Site VPN FortiGate ↔ Check Point (IKEv2, AES-256, SHA-256, VPN Community)
- [ ] 4.6 Logs & Monitor: SmartView, единая цепочка CP→Wazuh→Sentinel
- [x] 4.7 Policy Install Workflow: Verify → Install → скриншот

### ⏳ Блок 5 — Документация
- [ ] 5.1 GitHub репозиторий
- [ ] 5.2 README с архитектурой
- [ ] 5.3 Network diagram
- [ ] 5.4 Attack pipeline диаграмма
- [ ] 5.5 Все скриншоты

---

## Фраза для собеседования
"Я построил гибридный Security Lab: FortiGate как HQ файервол с сегментацией, IPS, WAF, DNAT. Site-to-Site IPsec VPN с Check Point. BGP/OSPF динамическая маршрутизация. Все события собираются в Wazuh и пересылаются в Microsoft Sentinel. Три сценария атак с полной цепочкой обнаружения."

## Связанные проекты
- Linux Security Lab: https://github.com/deniskapolishuk2012/linux-security-lab (9 компонентов, завершён)
- Azure Secure Foundation: https://github.com/deniskapolishuk2012/azure-secure-foundation (Terraform + M365 E5, завершён)
