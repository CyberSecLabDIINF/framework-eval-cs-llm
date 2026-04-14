

## Guía de recuperación — Tailscale en PC de la U

### Síntoma
```
tailscale status → unexpected state: NoState
```
O Tailscale no aparece conectado en https://login.tailscale.com/admin/machines

---

### Solución paso a paso

**Paso 1 — Intenta reconectar directamente:**
```bash
sudo tailscale up --force-reauth
```
Abre el link que aparece en el navegador e inicia sesión con `valenpaz22@gmail.com`.

**Paso 2 — Si no aparece ningún link:**
```bash
sudo tailscale logout
sudo tailscale up
```

**Paso 3 — Si sigue sin funcionar, reinicia el servicio:**
```bash
sudo systemctl restart tailscaled
sudo tailscale up --force-reauth
```

**Paso 4 — Verifica que quedó conectado:**
```bash
tailscale status
ip a | grep tailscale
```
Debe mostrar la IP `100.71.69.122`.

---

### Conectarte desde el notebook personal

Una vez que el PC de la U esté conectado a Tailscale:
```bash
ssh valentina@100.71.69.122
```

---

### Si el PC de la U se apagó y necesitas encenderlo remotamente

Desde cualquier dispositivo en la misma red física de la U (no funciona desde fuera), envía un magic packet con la MAC address de `enp6s0`. La MAC la puedes consultar ahora con:
```bash
ip a show enp6s0 | grep link/ether
```

