#Ensamblador Construccion:
#Primero se declaran todas las variables universales (lo que nunca #!/usr/bin/env python3
"""Ensamblador RV32I

Uso:
    python3 assembler_modular.py programa.asm programa.hex [programa.data.hex]

Organización del archivo (de arriba hacia abajo):

    0. Variables universales      direcciones, opcodes, funct7, registros, patrones
    1. Errores                    la excepción que usan todas las funciones
    2. Lectura de operandos       texto -> número (registro, inmediato, memoria, etiqueta)
    3. Los seis moldes            R, I, S, B, U, J: ponen cada campo en su lugar
    4. Una función por instrucción (39): add, sub, ..., jal
    5. Tabla de instrucciones     mnemónico -> (función, forma de los operandos)
    6. Pseudoinstrucciones        apodos -> instrucciones reales
    7. Segmento de datos          .word, .half, .byte, .string
    8. Lectura de líneas          comentarios, etiquetas, mnemónico, operandos
    9. Ensamblador en dos pasadas
   10. Programa principal

Regla de dependencias: cada sección solo usa las secciones que están ARRIBA de ella.
"""

import re
import sys


# ===========================================================================
# 0. VARIABLES UNIVERSALES
# ===========================================================================

# --- Mapa de memoria ---
DIRECCION_TEXTO = 0x00000000          # aquí empieza el programa (.text)
DIRECCION_DATOS = 0x10000000          # aquí empiezan los datos (.data)
TAMANO_INSTRUCCION = 4                # bytes por instrucción

# --- Opcodes (bits 6..0): dicen qué molde usar ---
OP_R      = 0b0110011                 # add, sub, ...
OP_I_ARIT = 0b0010011                 # addi, slti, ..., slli, srli, srai
OP_CARGA  = 0b0000011                 # lb, lh, lw, lbu, lhu
OP_JALR   = 0b1100111                 # jalr
OP_SISTEMA = 0b1110011                # ecall, ebreak
OP_S      = 0b0100011                 # sb, sh, sw
OP_B      = 0b1100011                 # beq, bne, blt, bge, bltu, bgeu
OP_LUI    = 0b0110111                 # lui
OP_AUIPC  = 0b0010111                 # auipc
OP_JAL    = 0b1101111                 # jal

# --- funct7: el desempate cuando funct3 se repite ---
F7_NORMAL = 0b0000000
F7_ALTERNO = 0b0100000                # sub, sra, srai

# --- Rangos de los inmediatos ---
RANGO_I = (-2048, 2047)               # 12 bits con signo (I y S)
RANGO_SHAMT = (0, 31)                 # 5 bits sin signo (slli, srli, srai)
RANGO_B = (-4096, 4094)               # 13 bits con signo, par
RANGO_U = (0, 0xFFFFF)                # 20 bits sin signo
RANGO_J = (-(1 << 20), (1 << 20) - 2) # 21 bits con signo, par

# --- Registros: por número (x0..x31) y por nombre ABI ---
REGISTROS = {f"x{i}": i for i in range(32)}
REGISTROS.update({"zero": 0, "ra": 1, "sp": 2, "gp": 3, "tp": 4,
                  "t0": 5, "t1": 6, "t2": 7, "s0": 8, "fp": 8, "s1": 9})
for i in range(8):
    REGISTROS[f"a{i}"] = 10 + i       # a0..a7  -> x10..x17
for i in range(2, 12):
    REGISTROS[f"s{i}"] = 16 + i       # s2..s11 -> x18..x27
for i in range(3, 7):
    REGISTROS[f"t{i}"] = 25 + i       # t3..t6  -> x28..x31

# --- Directivas de datos: nombre -> bytes por valor ---
DIRECTIVAS_DATOS = {".word": 4, ".half": 2, ".byte": 1}
DIRECTIVAS_CADENA = (".string", ".asciz")
ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", "\\": "\\", '"': '"'}

# --- Patrones de texto (expresiones regulares) ---
PATRON_ETIQUETA = re.compile(r"[A-Za-z_.$][A-Za-z0-9_.$]*")
PATRON_DEF_ETIQUETA = re.compile(r"\s*([A-Za-z_.$][A-Za-z0-9_.$]*)\s*:(.*)")
PATRON_INMEDIATO = re.compile(r"([+-]?)(0[xX][0-9a-fA-F]+|0[bB][01]+|[0-9]+)")
PATRON_MEMORIA = re.compile(r"(.*)\(\s*([^()]*?)\s*\)")
PATRON_CADENA = re.compile(r'"((?:[^"\\]|\\.)*)"')


# ===========================================================================
# 1. ERRORES
# ===========================================================================

class ErrorEnsamblador(Exception):
    """Error en una línea del programa fuente (se reporta con su número de línea)."""


# ===========================================================================
# 2. LECTURA DE OPERANDOS (texto -> número)
# ===========================================================================

def registro(texto):
    """'a0' o 'x10' -> 10."""
    nombre = texto.strip()
    if nombre not in REGISTROS:
        raise ErrorEnsamblador(f"registro inválido '{nombre}'")
    return REGISTROS[nombre]


def inmediato(texto):
    """'-3', '0x1F', '0b101' -> entero."""
    m = PATRON_INMEDIATO.fullmatch(texto.strip())
    if not m:
        raise ErrorEnsamblador(f"se esperaba un inmediato y se encontró '{texto.strip()}'")
    signo, digitos = m.groups()
    valor = int(digitos, 0) if digitos[:2].lower() in ("0x", "0b") else int(digitos, 10)
    return -valor if signo == "-" else valor


def memoria(texto):
    """'8(sp)' -> (8, 2). Devuelve (desplazamiento, número de registro)."""
    m = PATRON_MEMORIA.fullmatch(texto.strip())
    if not m:
        raise ErrorEnsamblador(f"se esperaba desplazamiento(registro) y se encontró '{texto.strip()}'")
    desplazamiento = m.group(1).strip()
    return (inmediato(desplazamiento) if desplazamiento else 0), registro(m.group(2))


def direccion_etiqueta(texto, simbolos):
    """'ciclo' -> dirección guardada en la tabla de símbolos."""
    nombre = texto.strip()
    if not PATRON_ETIQUETA.fullmatch(nombre):
        raise ErrorEnsamblador(f"se esperaba una etiqueta y se encontró '{nombre}'")
    if nombre not in simbolos:
        raise ErrorEnsamblador(f"etiqueta '{nombre}' no definida")
    return simbolos[nombre]


def es_simbolo(texto):
    """True si el operando es un nombre de etiqueta (y no desplazamiento(registro))."""
    return PATRON_ETIQUETA.fullmatch(texto.strip()) is not None


def esperar(mnemonico, operandos, cantidad):
    if len(operandos) != cantidad:
        raise ErrorEnsamblador(
            f"'{mnemonico}' espera {cantidad} operando(s) y recibió {len(operandos)}")


def verificar_rango(valor, rango, que="inmediato"):
    minimo, maximo = rango
    if not minimo <= valor <= maximo:
        raise ErrorEnsamblador(f"{que} {valor} fuera de rango [{minimo}, {maximo}]")


# ===========================================================================
# 3. LOS SEIS MOLDES: ponen cada campo en su posición de bits
# ===========================================================================

def molde_R(funct7, rs2, rs1, funct3, rd, opcode):
    # | funct7 31-25 | rs2 24-20 | rs1 19-15 | funct3 14-12 | rd 11-7 | opcode 6-0 |
    return (funct7 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode


def molde_I(imm, rs1, funct3, rd, opcode):
    # | imm[11:0] 31-20 | rs1 | funct3 | rd | opcode |
    verificar_rango(imm, RANGO_I)
    return ((imm & 0xFFF) << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode


def molde_S(imm, rs2, rs1, funct3, opcode):
    # | imm[11:5] 31-25 | rs2 | rs1 | funct3 | imm[4:0] 11-7 | opcode |
    verificar_rango(imm, RANGO_I)
    imm &= 0xFFF
    return ((imm >> 5) << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) \
        | ((imm & 0x1F) << 7) | opcode


def molde_B(desp, rs2, rs1, funct3, opcode):
    # | imm[12] 31 | imm[10:5] 30-25 | rs2 | rs1 | funct3 | imm[4:1] 11-8 | imm[11] 7 | opcode |
    if desp % 2 != 0:
        raise ErrorEnsamblador(f"desplazamiento de bifurcación {desp} no es par")
    verificar_rango(desp, RANGO_B, "desplazamiento de bifurcación")
    imm = desp & 0x1FFF
    return (((imm >> 12) & 0x1) << 31) | (((imm >> 5) & 0x3F) << 25) | (rs2 << 20) \
        | (rs1 << 15) | (funct3 << 12) | (((imm >> 1) & 0xF) << 8) \
        | (((imm >> 11) & 0x1) << 7) | opcode


def molde_U(imm, rd, opcode):
    # | imm[31:12] 31-12 | rd | opcode |
    verificar_rango(imm, RANGO_U)
    return (imm << 12) | (rd << 7) | opcode


def molde_J(desp, rd, opcode):
    # | imm[20] 31 | imm[10:1] 30-21 | imm[11] 20 | imm[19:12] 19-12 | rd | opcode |
    if desp % 2 != 0:
        raise ErrorEnsamblador(f"desplazamiento de salto {desp} no es par")
    verificar_rango(desp, RANGO_J, "desplazamiento de salto")
    imm = desp & 0x1FFFFF
    return (((imm >> 20) & 0x1) << 31) | (((imm >> 1) & 0x3FF) << 21) \
        | (((imm >> 11) & 0x1) << 20) | (((imm >> 12) & 0xFF) << 12) | (rd << 7) | opcode


# ===========================================================================
# 4. UNA FUNCIÓN DE CODIFICACIÓN POR INSTRUCCIÓN
#    Cada una recibe números ya leídos y devuelve la palabra de 32 bits.
# ===========================================================================

# ---- 4.1 Tipo R: rd = rs1 (op) rs2 ----
def cod_add(rd, rs1, rs2):  return molde_R(F7_NORMAL,  rs2, rs1, 0b000, rd, OP_R)
def cod_sub(rd, rs1, rs2):  return molde_R(F7_ALTERNO, rs2, rs1, 0b000, rd, OP_R)
def cod_sll(rd, rs1, rs2):  return molde_R(F7_NORMAL,  rs2, rs1, 0b001, rd, OP_R)
def cod_slt(rd, rs1, rs2):  return molde_R(F7_NORMAL,  rs2, rs1, 0b010, rd, OP_R)
def cod_sltu(rd, rs1, rs2): return molde_R(F7_NORMAL,  rs2, rs1, 0b011, rd, OP_R)
def cod_xor(rd, rs1, rs2):  return molde_R(F7_NORMAL,  rs2, rs1, 0b100, rd, OP_R)
def cod_srl(rd, rs1, rs2):  return molde_R(F7_NORMAL,  rs2, rs1, 0b101, rd, OP_R)
def cod_sra(rd, rs1, rs2):  return molde_R(F7_ALTERNO, rs2, rs1, 0b101, rd, OP_R)
def cod_or(rd, rs1, rs2):   return molde_R(F7_NORMAL,  rs2, rs1, 0b110, rd, OP_R)
def cod_and(rd, rs1, rs2):  return molde_R(F7_NORMAL,  rs2, rs1, 0b111, rd, OP_R)

# ---- 4.2 Tipo I aritméticas: rd = rs1 (op) imm ----
def cod_addi(rd, rs1, imm):  return molde_I(imm, rs1, 0b000, rd, OP_I_ARIT)
def cod_slti(rd, rs1, imm):  return molde_I(imm, rs1, 0b010, rd, OP_I_ARIT)
def cod_sltiu(rd, rs1, imm): return molde_I(imm, rs1, 0b011, rd, OP_I_ARIT)
def cod_xori(rd, rs1, imm):  return molde_I(imm, rs1, 0b100, rd, OP_I_ARIT)
def cod_ori(rd, rs1, imm):   return molde_I(imm, rs1, 0b110, rd, OP_I_ARIT)
def cod_andi(rd, rs1, imm):  return molde_I(imm, rs1, 0b111, rd, OP_I_ARIT)

# ---- 4.3 Tipo I corrimientos: el funct7 va en imm[11:5], shamt en imm[4:0] ----
def _corrimiento(rd, rs1, shamt, funct3, funct7):
    verificar_rango(shamt, RANGO_SHAMT, "desplazamiento")
    return molde_I((funct7 << 5) | shamt, rs1, funct3, rd, OP_I_ARIT)

def cod_slli(rd, rs1, shamt): return _corrimiento(rd, rs1, shamt, 0b001, F7_NORMAL)
def cod_srli(rd, rs1, shamt): return _corrimiento(rd, rs1, shamt, 0b101, F7_NORMAL)
def cod_srai(rd, rs1, shamt): return _corrimiento(rd, rs1, shamt, 0b101, F7_ALTERNO)

# ---- 4.4 Tipo I cargas: rd = Mem[rs1 + imm] ----
def cod_lb(rd, rs1, imm):  return molde_I(imm, rs1, 0b000, rd, OP_CARGA)
def cod_lh(rd, rs1, imm):  return molde_I(imm, rs1, 0b001, rd, OP_CARGA)
def cod_lw(rd, rs1, imm):  return molde_I(imm, rs1, 0b010, rd, OP_CARGA)
def cod_lbu(rd, rs1, imm): return molde_I(imm, rs1, 0b100, rd, OP_CARGA)
def cod_lhu(rd, rs1, imm): return molde_I(imm, rs1, 0b101, rd, OP_CARGA)

# ---- 4.5 Tipo I salto y sistema ----
def cod_jalr(rd, rs1, imm): return molde_I(imm, rs1, 0b000, rd, OP_JALR)
def cod_ecall():            return molde_I(0, 0, 0b000, 0, OP_SISTEMA)
def cod_ebreak():           return molde_I(1, 0, 0b000, 0, OP_SISTEMA)

# ---- 4.6 Tipo S: Mem[rs1 + imm] = rs2 ----
def cod_sb(rs2, rs1, imm): return molde_S(imm, rs2, rs1, 0b000, OP_S)
def cod_sh(rs2, rs1, imm): return molde_S(imm, rs2, rs1, 0b001, OP_S)
def cod_sw(rs2, rs1, imm): return molde_S(imm, rs2, rs1, 0b010, OP_S)

# ---- 4.7 Tipo B: si (rs1 cond rs2) PC = PC + desp ----
def cod_beq(rs1, rs2, desp):  return molde_B(desp, rs2, rs1, 0b000, OP_B)
def cod_bne(rs1, rs2, desp):  return molde_B(desp, rs2, rs1, 0b001, OP_B)
def cod_blt(rs1, rs2, desp):  return molde_B(desp, rs2, rs1, 0b100, OP_B)
def cod_bge(rs1, rs2, desp):  return molde_B(desp, rs2, rs1, 0b101, OP_B)
def cod_bltu(rs1, rs2, desp): return molde_B(desp, rs2, rs1, 0b110, OP_B)
def cod_bgeu(rs1, rs2, desp): return molde_B(desp, rs2, rs1, 0b111, OP_B)

# ---- 4.8 Tipo U ----
def cod_lui(rd, imm):   return molde_U(imm, rd, OP_LUI)
def cod_auipc(rd, imm): return molde_U(imm, rd, OP_AUIPC)

# ---- 4.9 Tipo J ----
def cod_jal(rd, desp): return molde_J(desp, rd, OP_JAL)


# ===========================================================================
# 5. TABLA DE INSTRUCCIONES
#    mnemónico -> (función de la sección 4, forma de los operandos en el texto)
# ===========================================================================

INSTRUCCIONES = {
    # R:  add rd, rs1, rs2
    "add": (cod_add, "rd,rs1,rs2"), "sub": (cod_sub, "rd,rs1,rs2"),
    "sll": (cod_sll, "rd,rs1,rs2"), "slt": (cod_slt, "rd,rs1,rs2"),
    "sltu": (cod_sltu, "rd,rs1,rs2"), "xor": (cod_xor, "rd,rs1,rs2"),
    "srl": (cod_srl, "rd,rs1,rs2"), "sra": (cod_sra, "rd,rs1,rs2"),
    "or": (cod_or, "rd,rs1,rs2"), "and": (cod_and, "rd,rs1,rs2"),
    # I:  addi rd, rs1, imm
    "addi": (cod_addi, "rd,rs1,imm"), "slti": (cod_slti, "rd,rs1,imm"),
    "sltiu": (cod_sltiu, "rd,rs1,imm"), "xori": (cod_xori, "rd,rs1,imm"),
    "ori": (cod_ori, "rd,rs1,imm"), "andi": (cod_andi, "rd,rs1,imm"),
    "slli": (cod_slli, "rd,rs1,imm"), "srli": (cod_srli, "rd,rs1,imm"),
    "srai": (cod_srai, "rd,rs1,imm"),
    # I cargas:  lw rd, imm(rs1)
    "lb": (cod_lb, "rd,imm(rs1)"), "lh": (cod_lh, "rd,imm(rs1)"),
    "lw": (cod_lw, "rd,imm(rs1)"), "lbu": (cod_lbu, "rd,imm(rs1)"),
    "lhu": (cod_lhu, "rd,imm(rs1)"),
    # I salto y sistema
    "jalr": (cod_jalr, "jalr"),
    "ecall": (cod_ecall, ""), "ebreak": (cod_ebreak, ""),
    # S:  sw rs2, imm(rs1)
    "sb": (cod_sb, "rs2,imm(rs1)"), "sh": (cod_sh, "rs2,imm(rs1)"),
    "sw": (cod_sw, "rs2,imm(rs1)"),
    # B:  beq rs1, rs2, etiqueta
    "beq": (cod_beq, "rs1,rs2,etiqueta"), "bne": (cod_bne, "rs1,rs2,etiqueta"),
    "blt": (cod_blt, "rs1,rs2,etiqueta"), "bge": (cod_bge, "rs1,rs2,etiqueta"),
    "bltu": (cod_bltu, "rs1,rs2,etiqueta"), "bgeu": (cod_bgeu, "rs1,rs2,etiqueta"),
    # U:  lui rd, imm20
    "lui": (cod_lui, "rd,imm"), "auipc": (cod_auipc, "rd,imm"),
    # J:  jal rd, etiqueta
    "jal": (cod_jal, "rd,etiqueta"),
}

CARGAS = {"lb", "lh", "lw", "lbu", "lhu"}
ALMACENAMIENTOS = {"sb", "sh", "sw"}


def leer_operandos(mnemonico, forma, ops, pc, simbolos):
    """Convierte los operandos de texto en los números que espera la función cod_xxx."""
    if forma == "rd,rs1,rs2":
        esperar(mnemonico, ops, 3)
        rs2, rs1, rd = registro(ops[2]), registro(ops[1]), registro(ops[0])
        return rd, rs1, rs2
    if forma == "rd,rs1,imm":
        esperar(mnemonico, ops, 3)
        imm, rs1, rd = inmediato(ops[2]), registro(ops[1]), registro(ops[0])
        return rd, rs1, imm
    if forma in ("rd,imm(rs1)", "rs2,imm(rs1)"):
        esperar(mnemonico, ops, 2)
        imm, rs1 = memoria(ops[1])
        return registro(ops[0]), rs1, imm
    if forma == "jalr":                      # jalr rd, imm(rs1)  o  jalr rd, rs1, imm
        if len(ops) == 3:
            return registro(ops[0]), registro(ops[1]), inmediato(ops[2])
        esperar(mnemonico, ops, 2)
        imm, rs1 = memoria(ops[1])
        return registro(ops[0]), rs1, imm
    if forma == "rs1,rs2,etiqueta":
        esperar(mnemonico, ops, 3)
        rs1, rs2 = registro(ops[0]), registro(ops[1])
        return rs1, rs2, direccion_etiqueta(ops[2], simbolos) - pc
    if forma == "rd,imm":
        esperar(mnemonico, ops, 2)
        return registro(ops[0]), inmediato(ops[1])
    if forma == "rd,etiqueta":
        esperar(mnemonico, ops, 2)
        rd = registro(ops[0])
        return rd, direccion_etiqueta(ops[1], simbolos) - pc
    if forma == "":
        esperar(mnemonico, ops, 0)
        return ()
    raise AssertionError(f"forma de operandos desconocida '{forma}'")


def codificar(mnemonico, ops, pc, simbolos):
    """Codifica UNA instrucción real: busca su función en la tabla y la llama."""
    funcion, forma = INSTRUCCIONES[mnemonico]
    return funcion(*leer_operandos(mnemonico, forma, ops, pc, simbolos))


# ===========================================================================
# 6. PSEUDOINSTRUCCIONES (apodos -> instrucciones reales)
# ===========================================================================

# Las de una sola instrucción: nombre -> (n.º de operandos, expansión)
PSEUDO_SIMPLES = {
    "nop":  (0, lambda o: [("addi", ["x0", "x0", "0"])]),
    "mv":   (2, lambda o: [("addi", [o[0], o[1], "0"])]),
    "not":  (2, lambda o: [("xori", [o[0], o[1], "-1"])]),
    "neg":  (2, lambda o: [("sub",  [o[0], "x0", o[1]])]),
    "seqz": (2, lambda o: [("sltiu", [o[0], o[1], "1"])]),
    "snez": (2, lambda o: [("sltu", [o[0], "x0", o[1]])]),
    "sltz": (2, lambda o: [("slt",  [o[0], o[1], "x0"])]),
    "sgtz": (2, lambda o: [("slt",  [o[0], "x0", o[1]])]),
    "beqz": (2, lambda o: [("beq",  [o[0], "x0", o[1]])]),
    "bnez": (2, lambda o: [("bne",  [o[0], "x0", o[1]])]),
    "blez": (2, lambda o: [("bge",  ["x0", o[0], o[1]])]),
    "bgez": (2, lambda o: [("bge",  [o[0], "x0", o[1]])]),
    "bltz": (2, lambda o: [("blt",  [o[0], "x0", o[1]])]),
    "bgtz": (2, lambda o: [("blt",  ["x0", o[0], o[1]])]),
    "bgt":  (3, lambda o: [("blt",  [o[1], o[0], o[2]])]),
    "ble":  (3, lambda o: [("bge",  [o[1], o[0], o[2]])]),
    "bgtu": (3, lambda o: [("bltu", [o[1], o[0], o[2]])]),
    "bleu": (3, lambda o: [("bgeu", [o[1], o[0], o[2]])]),
    "j":    (1, lambda o: [("jal",  ["x0", o[0]])]),
    "jr":   (1, lambda o: [("jalr", ["x0", f"0({o[0]})"])]),
    "ret":  (0, lambda o: [("jalr", ["x0", "0(x1)"])]),
}


def partir_hi_lo(v):
    """Separa v en hi (20 bits para lui/auipc) y lo (12 bits con signo para addi)."""
    hi = (v + 0x800) >> 12
    lo = v - (hi << 12)
    return hi & 0xFFFFF, lo


def valor_li(texto):
    v = inmediato(texto)
    verificar_rango(v, (-(1 << 31), (1 << 32) - 1))
    v &= 0xFFFFFFFF
    return v - (1 << 32) if v & 0x80000000 else v     # como entero de 32 bits con signo


def tamano(mnemonico, ops):
    """Cuántas instrucciones reales ocupa una línea. Se usa en la PRIMERA pasada."""
    if mnemonico in ("la", "call", "tail"):
        return 2
    if mnemonico in CARGAS and len(ops) == 2 and es_simbolo(ops[1]):
        return 2
    if mnemonico in ALMACENAMIENTOS and len(ops) == 3:
        return 2
    if mnemonico == "li":
        esperar("li", ops, 2)
        v = valor_li(ops[1])
        hi, lo = partir_hi_lo(v)
        return 1 if -2048 <= v <= 2047 or lo == 0 else 2
    if mnemonico in INSTRUCCIONES or mnemonico in PSEUDO_SIMPLES:
        return 1
    raise ErrorEnsamblador(f"instrucción inválida '{mnemonico}'")


def expandir(mnemonico, ops, pc, simbolos):
    """Convierte una línea en una lista de instrucciones reales [(mnemónico, operandos)]."""
    if mnemonico in PSEUDO_SIMPLES:
        cantidad, expansion = PSEUDO_SIMPLES[mnemonico]
        esperar(mnemonico, ops, cantidad)
        return expansion(ops)

    if mnemonico == "jal" and len(ops) == 1:             # jal L   -> jal x1, L
        return [("jal", ["x1", ops[0]])]
    if mnemonico == "jalr" and len(ops) == 1:            # jalr rs -> jalr x1, 0(rs)
        return [("jalr", ["x1", f"0({ops[0]})"])]

    if mnemonico == "li":
        esperar("li", ops, 2)
        v = valor_li(ops[1])
        if -2048 <= v <= 2047:
            return [("addi", [ops[0], "x0", str(v)])]
        hi, lo = partir_hi_lo(v)
        if lo == 0:
            return [("lui", [ops[0], str(hi)])]
        return [("lui", [ops[0], str(hi)]), ("addi", [ops[0], ops[0], str(lo)])]

    # Las demás usan auipc con la distancia v = símbolo - PC(del auipc)
    if mnemonico == "la":
        esperar("la", ops, 2)
        hi, lo = partir_hi_lo(direccion_etiqueta(ops[1], simbolos) - pc)
        return [("auipc", [ops[0], str(hi)]), ("addi", [ops[0], ops[0], str(lo)])]

    if mnemonico in CARGAS and len(ops) == 2 and es_simbolo(ops[1]):
        hi, lo = partir_hi_lo(direccion_etiqueta(ops[1], simbolos) - pc)
        return [("auipc", [ops[0], str(hi)]), (mnemonico, [ops[0], f"{lo}({ops[0]})"])]

    if mnemonico in ALMACENAMIENTOS and len(ops) == 3:   # sw rs, símbolo, rt
        hi, lo = partir_hi_lo(direccion_etiqueta(ops[1], simbolos) - pc)
        return [("auipc", [ops[2], str(hi)]), (mnemonico, [ops[0], f"{lo}({ops[2]})"])]

    if mnemonico == "call":
        esperar("call", ops, 1)
        hi, lo = partir_hi_lo(direccion_etiqueta(ops[0], simbolos) - pc)
        return [("auipc", ["x1", str(hi)]), ("jalr", ["x1", f"{lo}(x1)"])]

    if mnemonico == "tail":
        esperar("tail", ops, 1)
        hi, lo = partir_hi_lo(direccion_etiqueta(ops[0], simbolos) - pc)
        return [("auipc", ["x6", str(hi)]), ("jalr", ["x0", f"{lo}(x6)"])]

    return [(mnemonico, ops)]                            # ya es una instrucción real


# ===========================================================================
# 7. SEGMENTO DE DATOS
# ===========================================================================

def decodificar_cadena(texto):
    m = PATRON_CADENA.fullmatch(texto.strip())
    if not m:
        raise ErrorEnsamblador(f"cadena mal formada: {texto.strip()}")
    resultado, i, s = [], 0, m.group(1)
    while i < len(s):
        if s[i] == "\\":
            if s[i + 1] not in ESCAPES:
                raise ErrorEnsamblador(f"secuencia de escape desconocida '\\{s[i + 1]}'")
            resultado.append(ESCAPES[s[i + 1]])
            i += 2
        else:
            resultado.append(s[i])
            i += 1
    return "".join(resultado).encode("utf-8") + b"\0"


def tamano_datos(directiva, ops, texto_ops):
    if directiva in DIRECTIVAS_CADENA:
        return len(decodificar_cadena(texto_ops))
    if not ops or any(o == "" for o in ops):
        raise ErrorEnsamblador(f"{directiva} requiere al menos un valor")
    return DIRECTIVAS_DATOS[directiva] * len(ops)


def emitir_datos(directiva, ops, texto_ops, simbolos):
    if directiva in DIRECTIVAS_CADENA:
        return decodificar_cadena(texto_ops)
    n = DIRECTIVAS_DATOS[directiva]
    salida = bytearray()
    for op in ops:
        if n == 4 and es_simbolo(op):                    # .word etiqueta
            valor = direccion_etiqueta(op, simbolos)
        else:
            valor = inmediato(op)
            verificar_rango(valor, (-(1 << (8 * n - 1)), (1 << (8 * n)) - 1), "valor")
        salida += (valor & ((1 << (8 * n)) - 1)).to_bytes(n, "little")
    return bytes(salida)


# ===========================================================================
# 8. LECTURA DE LÍNEAS
# ===========================================================================

def quitar_comentario(linea):
    dentro_de_cadena = False
    for i, c in enumerate(linea):
        if c == '"' and (i == 0 or linea[i - 1] != "\\"):
            dentro_de_cadena = not dentro_de_cadena
        elif c == "#" and not dentro_de_cadena:
            return linea[:i]
    return linea


def analizar_linea(linea):
    """Devuelve (etiquetas, mnemónico, operandos, texto de operandos)."""
    resto = quitar_comentario(linea)
    etiquetas = []
    while True:
        m = PATRON_DEF_ETIQUETA.match(resto)
        if not m:
            break
        etiquetas.append(m.group(1))
        resto = m.group(2)
    resto = resto.strip()
    if not resto:
        return etiquetas, None, [], ""
    partes = resto.split(None, 1)
    mnemonico = partes[0].lower()
    texto_ops = partes[1].strip() if len(partes) > 1 else ""
    ops = [o.strip() for o in texto_ops.split(",")] if texto_ops else []
    if mnemonico not in DIRECTIVAS_CADENA + tuple(DIRECTIVAS_DATOS) and "" in ops:
        raise ErrorEnsamblador("operando vacío (¿coma de más?)")
    return etiquetas, mnemonico, ops, texto_ops


# ===========================================================================
# 9. ENSAMBLADOR EN DOS PASADAS
# ===========================================================================

def primera_pasada(fuente, error):
    """Calcula la dirección de cada línea y llena la tabla de símbolos."""
    simbolos, lineas = {}, []
    segmento = "text"
    contador = {"text": DIRECCION_TEXTO, "data": DIRECCION_DATOS}
    for numero, linea in enumerate(fuente.splitlines(), start=1):
        try:
            etiquetas, mnemonico, ops, texto_ops = analizar_linea(linea)
            for etiqueta in etiquetas:
                if etiqueta in simbolos:
                    raise ErrorEnsamblador(f"etiqueta '{etiqueta}' duplicada")
                simbolos[etiqueta] = contador[segmento]
            if mnemonico is None:
                continue
            if mnemonico in (".text", ".data"):
                esperar(mnemonico, ops, 0)
                segmento = mnemonico[1:]
            elif mnemonico in (".globl", ".global"):
                pass                                      # sin efecto en este ensamblador
            elif mnemonico in DIRECTIVAS_DATOS or mnemonico in DIRECTIVAS_CADENA:
                if segmento != "data":
                    raise ErrorEnsamblador(f"la directiva {mnemonico} solo se permite en .data")
                n = tamano_datos(mnemonico, ops, texto_ops)
                lineas.append((numero, "data", contador["data"], mnemonico, ops, texto_ops))
                contador["data"] += n
            elif mnemonico.startswith("."):
                raise ErrorEnsamblador(f"directiva desconocida '{mnemonico}'")
            else:
                if segmento != "text":
                    raise ErrorEnsamblador("las instrucciones solo se permiten en .text")
                n = tamano(mnemonico, ops)
                lineas.append((numero, "text", contador["text"], mnemonico, ops, texto_ops))
                contador["text"] += TAMANO_INSTRUCCION * n
        except ErrorEnsamblador as e:
            error(numero, e)
    return simbolos, lineas


def segunda_pasada(lineas, simbolos, error):
    """Codifica cada línea usando la tabla de símbolos ya completa."""
    palabras, datos = [], bytearray()
    for numero, seg, direccion, mnemonico, ops, texto_ops in lineas:
        try:
            if seg == "data":
                datos += emitir_datos(mnemonico, ops, texto_ops, simbolos)
            else:
                pc = direccion
                for real, real_ops in expandir(mnemonico, ops, pc, simbolos):
                    palabras.append(codificar(real, real_ops, pc, simbolos))
                    pc += TAMANO_INSTRUCCION
        except ErrorEnsamblador as e:
            error(numero, e)
    return palabras, bytes(datos)


def ensamblar(fuente, nombre_archivo="programa.asm"):
    """Devuelve (palabras de texto, bytes de datos, lista de errores)."""
    errores = []

    def error(numero, mensaje):
        errores.append((numero, f"{nombre_archivo}:{numero}: error: {mensaje}"))

    simbolos, lineas = primera_pasada(fuente, error)
    palabras, datos = segunda_pasada(lineas, simbolos, error)
    errores.sort(key=lambda e: e[0])                     # en orden de línea
    return palabras, datos, [mensaje for _, mensaje in errores]


# ===========================================================================
# 10. PROGRAMA PRINCIPAL
# ===========================================================================

def palabras_de_datos(datos):
    """Agrupa los bytes de .data en palabras de 32 bits little-endian."""
    datos = datos + b"\0" * (-len(datos) % 4)
    return [int.from_bytes(datos[i:i + 4], "little") for i in range(0, len(datos), 4)]


def escribir_hex(ruta, palabras):
    with open(ruta, "w") as f:
        for p in palabras:
            f.write(f"{p:08x}\n")


def main(argv):
    if len(argv) not in (3, 4):
        print("uso: python3 assembler_modular.py programa.asm programa.hex [programa.data.hex]",
              file=sys.stderr)
        return 2
    entrada, salida = argv[1], argv[2]
    try:
        with open(entrada, encoding="utf-8") as f:
            fuente = f.read()
    except OSError as e:
        print(f"error: no se pudo leer '{entrada}': {e.strerror}", file=sys.stderr)
        return 1

    palabras, datos, errores = ensamblar(fuente, entrada)
    if errores:
        for mensaje in errores:
            print(mensaje, file=sys.stderr)
        return 1

    escribir_hex(salida, palabras)
    if len(argv) == 4:
        escribir_hex(argv[3], palabras_de_datos(datos))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
