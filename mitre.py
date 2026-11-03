"""Conservative MITRE ATT&CK® technique alignment for Aegis SIEM findings.

This module maps local heuristic findings to candidate ATT&CK techniques. A mapping
is a triage aid, not proof of adversary behavior. Technique metadata was checked
against the official MITRE ATT&CK Enterprise website on 2026-10-31.
"""
from __future__ import annotations

from typing import Any

ATTACK_REFERENCE_AS_OF = "2026-10-31"

TECHNIQUES: dict[str, dict[str, Any]] = {
    "T1110.001": {
        "name": "Password Guessing",
        "tactics": ["Credential Access"],
        "url": "https://attack.mitre.org/techniques/T1110/001/",
        "rationale": "Repeated failed authentication attempts against the same account/source can be consistent with password guessing.",
        "rationale_es": "Los intentos repetidos de autenticación fallida contra la misma cuenta/origen pueden ser compatibles con adivinación de contraseñas.",
    },
    "T1059.001": {
        "name": "PowerShell",
        "tactics": ["Execution"],
        "url": "https://attack.mitre.org/techniques/T1059/001/",
        "rationale": "The observed command pattern identifies PowerShell or PowerShell-based script execution.",
        "rationale_es": "El patrón de comando observado identifica PowerShell o la ejecución de scripts basados en PowerShell.",
    },
    "T1027.010": {
        "name": "Command Obfuscation",
        "tactics": ["Stealth"],
        "url": "https://attack.mitre.org/techniques/T1027/010/",
        "rationale": "Encoded or transformed command content can be used to make command-line activity harder to inspect.",
        "rationale_es": "El contenido de comandos codificado o transformado puede dificultar la inspección de la actividad de línea de comandos.",
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactics": ["Command and Control"],
        "url": "https://attack.mitre.org/techniques/T1105/",
        "rationale": "A command pattern associated with fetching content may indicate transfer of a tool or file into an environment.",
        "rationale_es": "Un patrón de comando asociado con la descarga de contenido puede indicar la transferencia de una herramienta o archivo al entorno.",
    },
    "T1197": {
        "name": "BITS Jobs",
        "tactics": ["Persistence", "Defense Evasion", "Execution"],
        "url": "https://attack.mitre.org/techniques/T1197/",
        "rationale": "The observed BITSAdmin transfer syntax may align with abuse of Background Intelligent Transfer Service jobs.",
        "rationale_es": "La sintaxis de transferencia BITSAdmin observada puede corresponder al abuso de tareas del servicio Background Intelligent Transfer Service.",
    },
    "T1218.005": {
        "name": "Mshta",
        "tactics": ["Stealth"],
        "url": "https://attack.mitre.org/techniques/T1218/005/",
        "rationale": "The command line references mshta.exe, a Windows utility that can proxy execution of HTA or script content.",
        "rationale_es": "La línea de comandos menciona mshta.exe, una utilidad de Windows que puede ejecutar contenido HTA o scripts mediante proxy.",
    },
    "T1218.010": {
        "name": "Regsvr32",
        "tactics": ["Stealth"],
        "url": "https://attack.mitre.org/techniques/T1218/010/",
        "rationale": "The command line references regsvr32.exe, which can be abused to proxy execution of script or DLL content.",
        "rationale_es": "La línea de comandos menciona regsvr32.exe, que puede abusarse para ejecutar scripts o DLL mediante proxy.",
    },
    "T1218.011": {
        "name": "Rundll32",
        "tactics": ["Stealth"],
        "url": "https://attack.mitre.org/techniques/T1218/011/",
        "rationale": "The command line references rundll32.exe, which can be abused to proxy execution of DLL or script content.",
        "rationale_es": "La línea de comandos menciona rundll32.exe, que puede abusarse para ejecutar DLL o scripts mediante proxy.",
    },
    "T1059.005": {
        "name": "Visual Basic",
        "tactics": ["Execution"],
        "url": "https://attack.mitre.org/techniques/T1059/005/",
        "rationale": "wscript.exe or cscript.exe can be used to execute VBScript on Windows; the command context still needs validation.",
        "rationale_es": "wscript.exe o cscript.exe pueden ejecutar VBScript en Windows; el contexto del comando todavía debe validarse.",
    },
    "T1003.001": {
        "name": "LSASS Memory",
        "tactics": ["Credential Access"],
        "url": "https://attack.mitre.org/techniques/T1003/001/",
        "rationale": "The matched Mimikatz, sekurlsa, or LSASS indicator is consistent with possible access to LSASS credential material.",
        "rationale_es": "El indicador Mimikatz, sekurlsa o LSASS coincide con un posible acceso al material de credenciales de LSASS.",
    },
    "T1490": {
        "name": "Inhibit System Recovery",
        "tactics": ["Impact"],
        "url": "https://attack.mitre.org/techniques/T1490/",
        "rationale": "The matched command attempts to delete volume shadow copies or a backup catalog, which can inhibit recovery.",
        "rationale_es": "El comando detectado intenta eliminar copias sombra de volumen o un catálogo de respaldo, lo que puede impedir la recuperación.",
    },
    "T1685.005": {
        "name": "Clear Windows Event Logs",
        "tactics": ["Defense Impairment"],
        "url": "https://attack.mitre.org/techniques/T1685/005/",
        "rationale": "The log-clearing event or message aligns with clearing Windows Event Logs to hide activity.",
        "rationale_es": "El evento o mensaje de borrado de registros coincide con la limpieza de registros de Windows para ocultar actividad.",
    },
    "T1098.007": {
        "name": "Additional Local or Domain Groups",
        "tactics": ["Persistence", "Privilege Escalation"],
        "url": "https://attack.mitre.org/techniques/T1098/007/",
        "rationale": "A group-membership change affecting privileged local or domain groups can align with adding an account to additional groups.",
        "rationale_es": "Un cambio de pertenencia a grupos privilegiados locales o de dominio puede coincidir con agregar una cuenta a grupos adicionales.",
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactics": ["Discovery"],
        "url": "https://attack.mitre.org/techniques/T1046/",
        "rationale": "Contact with many unique destination IPs can be consistent with network discovery, but this rule does not inspect ports or prove scanning.",
        "rationale_es": "El contacto con muchas IP de destino únicas puede ser compatible con descubrimiento de red, pero esta regla no inspecciona puertos ni demuestra un escaneo.",
    },
}


def map_finding(
    rule: str,
    title: str,
    event_texts: list[str] | None = None,
    event_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Return candidate technique records and a transparent mapping caveat."""
    texts = " ".join(str(x) for x in (event_texts or [])).casefold()
    ids = {str(x).strip() for x in (event_ids or []) if str(x).strip()}
    title_fold = str(title).casefold()
    technique_ids: list[str] = []
    note = "No defensible ATT&CK mapping from the available telemetry alone."
    note_es = "No existe una asignación ATT&CK defendible únicamente con la telemetría disponible."

    if rule in {"AUTH-BURST", "AUTH-SUCCESS-AFTER-FAIL"}:
        technique_ids = ["T1110.001"]
        note = (
            "Candidate alignment only. The rule groups failures by source and/or account; it does not establish malicious intent, "
            "and it does not specifically detect Password Spraying across many accounts (T1110.003)."
        )
        note_es = (
            "Alineación candidata únicamente. La regla agrupa fallos por origen y/o cuenta; no demuestra intención maliciosa "
            "ni detecta específicamente Password Spraying entre múltiples cuentas (T1110.003)."
        )
    elif rule == "EXEC-SUSPICIOUS":
        if "encoded powershell" in title_fold or "-enc" in texts or "frombase64string" in texts:
            technique_ids = ["T1059.001", "T1027.010"]
            note = "Candidate alignment based on an encoded PowerShell command pattern; decoding and reviewing the full command is required."
            note_es = "Alineación candidata basada en un patrón de PowerShell codificado; se debe decodificar y revisar el comando completo."
        elif "download cradle" in title_fold or "downloadstring" in texts or "invoke-webrequest" in texts or "downloadfile" in texts:
            technique_ids = ["T1059.001", "T1105"]
            note = "Candidate alignment based on PowerShell/script content retrieval; confirm the destination, payload, parent process, and execution result."
            note_es = "Alineación candidata basada en la obtención de contenido mediante PowerShell/scripts; confirma destino, archivo, proceso padre y resultado de ejecución."
        elif "download utility" in title_fold:
            if "bitsadmin" in texts:
                technique_ids = ["T1197"]
                note = "Candidate alignment because BITSAdmin transfer syntax was matched; legitimate software and update workflows also use BITS."
                note_es = "Alineación candidata porque coincidió sintaxis de transferencia BITSAdmin; software legítimo y actualizaciones también usan BITS."
            elif "certutil" in texts:
                technique_ids = ["T1105"]
                note = "Candidate alignment because certutil URL-cache syntax may transfer content; verify the file, source, destination, and process context."
                note_es = "Alineación candidata porque la sintaxis URL-cache de certutil puede transferir contenido; valida archivo, origen, destino y contexto del proceso."
        elif "lolbin" in title_fold:
            if "mshta" in texts:
                technique_ids.append("T1218.005")
            if "regsvr32" in texts:
                technique_ids.append("T1218.010")
            if "rundll32" in texts:
                technique_ids.append("T1218.011")
            if "wscript" in texts or "cscript" in texts:
                technique_ids.append("T1059.005")
            if technique_ids:
                note = "Candidate alignment based on the named Windows utility only; inspect arguments, parent process, signer, network activity, and expected administrative use."
                note_es = "Alineación candidata basada únicamente en la utilidad de Windows identificada; inspecciona argumentos, proceso padre, firma, red y uso administrativo esperado."
        elif "credential-dumping" in title_fold or "credential dumping" in title_fold or "mimikatz" in texts or "sekurlsa" in texts or "lsass.exe" in texts:
            technique_ids = ["T1003.001"]
            note = "Candidate alignment from a credential-dumping keyword/LSASS indicator. The string match alone does not confirm memory access or credential theft."
            note_es = "Alineación candidata por una palabra clave de extracción de credenciales/LSASS. La coincidencia de texto no confirma acceso a memoria ni robo de credenciales."
        elif "shadow-copy" in title_fold or "backup deletion" in title_fold or "vssadmin" in texts or "wbadmin" in texts:
            technique_ids = ["T1490"]
            note = "Candidate alignment based on a command associated with deleting shadow copies or backup catalog data; verify command outcome and authorization."
            note_es = "Alineación candidata basada en un comando asociado con borrar copias sombra o catálogos de respaldo; verifica resultado y autorización."
    elif rule == "DEFENSE-EVASION-LOG-CLEAR":
        technique_ids = ["T1685.005"]
        note = "Current Enterprise ATT&CK mapping. Validate the event source and exact log targeted; this rule's text pattern may also match non-Windows/vendor-specific messages."
        note_es = "Asignación vigente de ATT&CK Enterprise. Valida el origen del evento y el registro afectado; el patrón también puede coincidir con mensajes de otros proveedores."
    elif rule == "IDENTITY-PRIVILEGE":
        if ids.intersection({"4728", "4732", "4756"}) or any(term in texts for term in ["added to administrators", "added to privileged", "privileged group membership"]):
            technique_ids = ["T1098.007"]
            note = "Candidate alignment for group-membership change events (4728/4732/4756 or equivalent message). Event ID 4672 alone means special privileges were assigned; it does not prove group membership changed."
            note_es = "Alineación candidata para eventos de cambio de grupos (4728/4732/4756 o mensaje equivalente). El ID 4672 por sí solo indica asignación de privilegios especiales; no prueba un cambio de grupo."
        else:
            note = "This alert may reflect privileged logon rights (for example, Event ID 4672). That telemetry alone does not establish an ATT&CK technique, so no technique is assigned."
            note_es = "Esta alerta puede reflejar derechos de inicio privilegiado (por ejemplo, evento 4672). Esa telemetría no establece por sí sola una técnica ATT&CK; no se asigna técnica."
    elif rule == "NETWORK-FANOUT":
        technique_ids = ["T1046"]
        note = "Low-specificity candidate. The rule counts unique destination IPs across the supplied export; it does not inspect destination ports, probe behavior, success, or a bounded time window."
        note_es = "Candidato de baja especificidad. La regla cuenta IP de destino únicas en la exportación; no inspecciona puertos, sondeos, éxito ni una ventana temporal delimitada."
    elif rule == "DATA-LARGE-EGRESS":
        note = "Not mapped. Transfer volume alone cannot distinguish routine backups/synchronization from exfiltration; destination, process, protocol, data sensitivity, and context are absent or not correlated."
        note_es = "Sin asignación. El volumen transferido no distingue respaldos/sincronización de exfiltración; faltan o no están correlacionados destino, proceso, protocolo, sensibilidad y contexto."
    elif rule == "VENDOR-HIGH-SEVERITY":
        note = "Not mapped. This is a vendor-severity carry-forward, not a behavior-specific detection; inspect the originating alert and its supporting telemetry."
        note_es = "Sin asignación. Es una alerta conservada por severidad del proveedor, no una detección de comportamiento específica; revisa la alerta original y su telemetría."

    records = [
        {
            "id": tid,
            "name": TECHNIQUES[tid]["name"],
            "tactics": list(TECHNIQUES[tid]["tactics"]),
            "url": TECHNIQUES[tid]["url"],
            "rationale": TECHNIQUES[tid]["rationale"],
            "rationale_es": TECHNIQUES[tid]["rationale_es"],
            "assessment": "Potential alignment",
            "assessment_es": "Alineación potencial",
        }
        for tid in dict.fromkeys(technique_ids)
        if tid in TECHNIQUES
    ]
    return {
        "techniques": records,
        "note": note,
        "note_es": note_es,
        "assessment": "Potential alignment" if records else "Not mapped from available telemetry",
        "assessment_es": "Alineación potencial" if records else "Sin asignación con la telemetría disponible",
    }


def technique_catalog() -> dict[str, dict[str, Any]]:
    """Return a shallow-copy catalog for documentation and tests."""
    return {key: dict(value) for key, value in TECHNIQUES.items()}
