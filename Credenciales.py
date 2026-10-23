import sqlite3
import re
import bcrypt
import getpass
import time
import logging

# Configuración del sistema de registros (Logs)
logging.basicConfig(
    filename="sistema.log",
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

DB_NAME = "seguridad_credenciales_pro.db"
MAX_INTENTOS_LOGIN = 3
TIEMPO_BLOQUEO_SEGUNDOS = 30  # Tiempo de bloqueo tras agotar intentos

def inicializar_base_datos():
    """Crea la base de datos y la tabla con campos avanzados de seguridad."""
    conexion = sqlite3.connect(DB_NAME)
    cursor = conexion.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS credenciales (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario TEXT UNIQUE NOT NULL,
            password_hash BLOB NOT NULL,
            rol TEXT NOT NULL DEFAULT 'usuario',
            intentos_fallidos INTEGER DEFAULT 0,
            bloqueado_hasta REAL DEFAULT 0,
            fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conexion.commit()
    conexion.close()

def validar_fortaleza_password(password):
    """Verifica los estándares mínimos de seguridad de la contraseña."""
    if len(password) < 8:
        return False, "[ERROR] La contraseña debe tener al menos 8 caracteres."
    if not re.search(r"[A-Z]", password):
        return False, "[ERROR] La contraseña debe contener al menos una letra mayúscula."
    if not re.search(r"[a-z]", password):
        return False, "[ERROR] La contraseña debe contener al menos una letra minúscula."
    if not re.search(r"\d", password):
        return False, "[ERROR] La contraseña debe contener al menos un número."
    return True, "Contraseña válida."

def registrar_usuario():
    """Registra un nuevo usuario asignando rol automáticamente (el primero es admin)."""
    print("\n--- REGISTRO DE NUEVO USUARIO ---")
    usuario = input("Ingresa el nombre de usuario: ").strip()
    
    if not usuario:
        print("[ERROR] El nombre de usuario no puede estar vacío.")
        return

    password = getpass.getpass("Ingresa la contraseña: ")
    confirm_password = getpass.getpass("Confirma la contraseña: ")

    if password != confirm_password:
        print("[ERROR] Las contraseñas no coinciden.")
        return

    valida, mensaje = validar_fortaleza_password(password)
    if not valida:
        print(mensaje)
        return

    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    password_hash = bcrypt.hashpw(password_bytes, salt)

    try:
        conexion = sqlite3.connect(DB_NAME)
        cursor = conexion.cursor()
        
        # Verificar si es el primer usuario para asignarle rol de Administrador
        cursor.execute("SELECT COUNT(*) FROM credenciales")
        total_usuarios = cursor.fetchone()[0]
        rol = "admin" if total_usuarios == 0 else "usuario"

        cursor.execute(
            "INSERT INTO credenciales (usuario, password_hash, rol) VALUES (?, ?, ?)", 
            (usuario, password_hash, rol)
        )
        conexion.commit()
        print(f"[EXITO] Usuario '{usuario}' registrado exitosamente con rol de [{rol}].")
        logging.info(f"Nuevo usuario registrado: {usuario} con rol {rol}")
    except sqlite3.IntegrityError:
        print(f"[ERROR] El nombre de usuario '{usuario}' ya existe.")
        logging.warning(f"Intento fallido de registro con usuario existente: {usuario}")
    finally:
        conexion.close()

def iniciar_sesion():
    """Verifica credenciales manejando bloqueo persistente de cuenta."""
    print("\n--- INICIO DE SESIÓN ---")
    usuario = input("Usuario: ").strip()

    conexion = sqlite3.connect(DB_NAME)
    cursor = conexion.cursor()
    cursor.execute("SELECT id, password_hash, intentos_fallidos, bloqueado_hasta, rol FROM credenciales WHERE usuario = ?", (usuario,))
    resultado = cursor.fetchone()

    if not resultado:
        print("[ERROR] El usuario especificado no existe.")
        conexion.close()
        logging.warning(f"Intento de inicio de sesión con usuario inexistente: {usuario}")
        return False

    user_id, password_hash_almacenado, intentos_fallidos, bloqueado_hasta, rol = resultado
    tiempo_actual = time.time()

    # Comprobar si la cuenta se encuentra bloqueada temporalmente
    if bloqueado_hasta > tiempo_actual:
        tiempo_restante = int(bloqueado_hasta - tiempo_actual)
        print(f"[BLOQUEADO] Cuenta suspendida temporalmente. Inténtalo en {tiempo_restante} segundos.")
        conexion.close()
        return False

    password = getpass.getpass("Contraseña: ")
    password_bytes = password.encode('utf-8')

    if bcrypt.checkpw(password_bytes, password_hash_almacenado):
        # Restablecer intentos fallidos tras un acceso exitoso
        cursor.execute("UPDATE credenciales SET intentos_fallidos = 0, bloqueado_hasta = 0 WHERE id = ?", (user_id,))
        conexion.commit()
        conexion.close()
        print(f"[ACCESO CONCEDIDO] Bienvenido/a, {usuario} (Rol: {rol}).")
        logging.info(f"Inicio de sesión exitoso: {usuario}")
        return True
    else:
        # Incrementar contador de fallos
        intentos_fallidos += 1
        if intentos_fallidos >= MAX_INTENTOS_LOGIN:
            nuevo_bloqueo = time.time() + TIEMPO_BLOQUEO_SEGUNDOS
            cursor.execute("UPDATE credenciales SET intentos_fallidos = ?, bloqueado_hasta = ? WHERE id = ?", (intentos_fallidos, nuevo_bloqueo, user_id))
            conexion.commit()
            print(f"[BLOQUEADO] Demasiados intentos fallidos. Cuenta bloqueada por {TIEMPO_BLOQUEO_SEGUNDOS} segundos.")
            logging.error(f"Cuenta bloqueada por seguridad debido a intentos fallidos: {usuario}")
        else:
            cursor.execute("UPDATE credenciales SET intentos_fallidos = ? WHERE id = ?", (intentos_fallidos, user_id))
            conexion.commit()
            print(f"[ERROR] Contraseña incorrecta. Intentos restantes: {MAX_INTENTOS_LOGIN - intentos_fallidos}")
            logging.warning(f"Contraseña incorrecta para el usuario: {usuario}")
        
        conexion.close()
        return False

def listar_usuarios():
    """Muestra la lista de usuarios registrados (Función orientada a auditoría)."""
    print("\n--- USUARIOS REGISTRADOS ---")
    conexion = sqlite3.connect(DB_NAME)
    cursor = conexion.cursor()
    cursor.execute("SELECT id, usuario, rol, fecha_registro FROM credenciales")
    usuarios = cursor.fetchall()
    conexion.close()

    if not usuarios:
        print("No hay usuarios registrados en la base de datos.")
        return

    print(f"{'ID':<5} | {'Usuario':<15} | {'Rol':<10} | {'Fecha de Registro'}")
    print("-" * 60)
    for u in usuarios:
        print(f"{u[0]:<5} | {u[1]:<15} | {u[2]:<10} | {u[3]}")
    logging.info("Se consultó la lista de usuarios registrados.")

def cambiar_password():
    """Permite actualizar la contraseña previa verificación de la actual."""
    print("\n--- CAMBIO DE CONTRASEÑA ---")
    usuario = input("Ingresa tu nombre de usuario: ").strip()
    
    conexion = sqlite3.connect(DB_NAME)
    cursor = conexion.cursor()
    cursor.execute("SELECT password_hash FROM credenciales WHERE usuario = ?", (usuario,))
    resultado = cursor.fetchone()

    if not resultado:
        print("[ERROR] El usuario no existe.")
        conexion.close()
        return

    password_hash_almacenado = resultado[0]
    password_actual = getpass.getpass("Ingresa tu contraseña actual: ")

    if not bcrypt.checkpw(password_actual.encode('utf-8'), password_hash_almacenado):
        print("[ERROR] La contraseña actual es incorrecta.")
        conexion.close()
        logging.warning(f"Fallo al cambiar contraseña (actual incorrecta) para: {usuario}")
        return

    nueva_password = getpass.getpass("Ingresa la nueva contraseña: ")
    confirm_password = getpass.getpass("Confirma la nueva contraseña: ")

    if nueva_password != confirm_password:
        print("[ERROR] Las contraseñas no coinciden.")
        conexion.close()
        return

    valida, mensaje = validar_fortaleza_password(nueva_password)
    if not valida:
        print(mensaje)
        conexion.close()
        return

    nuevo_hash = bcrypt.hashpw(nueva_password.encode('utf-8'), bcrypt.gensalt())
    cursor.execute("UPDATE credenciales SET password_hash = ? WHERE usuario = ?", (nuevo_hash, usuario))
    conexion.commit()
    conexion.close()
    print("[EXITO] La contraseña ha sido actualizada correctamente.")
    logging.info(f"Contraseña actualizada con éxito para el usuario: {usuario}")

def eliminar_usuario():
    """Elimina un usuario de la base de datos tras confirmar su identidad."""
    print("\n--- ELIMINAR CUENTA DE USUARIO ---")
    usuario = input("Ingresa el usuario a eliminar: ").strip()

    conexion = sqlite3.connect(DB_NAME)
    cursor = conexion.cursor()
    cursor.execute("SELECT password_hash FROM credenciales WHERE usuario = ?", (usuario,))
    resultado = cursor.fetchone()

    if not resultado:
        print("[ERROR] El usuario no existe.")
        conexion.close()
        return

    password = getpass.getpass("Confirma con la contraseña del usuario: ")
    if not bcrypt.checkpw(password.encode('utf-8'), resultado[0]):
        print("[ERROR] Contraseña incorrecta. No se pudo eliminar el usuario.")
        conexion.close()
        logging.warning(f"Intento fallido de eliminar usuario por contraseña incorrecta: {usuario}")
        return

    confirmacion = input(f"¿Estás seguro de que deseas eliminar permanentemente a '{usuario}'? (s/n): ").strip().lower()
    if confirmacion == 's':
        cursor.execute("DELETE FROM credenciales WHERE usuario = ?", (usuario,))
        conexion.commit()
        print(f"[EXITO] El usuario '{usuario}' ha sido eliminado del sistema.")
        logging.info(f"Usuario eliminado permanentemente: {usuario}")
    else:
        print("[CANCELADO] Operación cancelada.")
    
    conexion.close()

def menu_principal():
    """Menú interactivo principal del sistema."""
    inicializar_base_datos()
    
    while True:
        print("\n========================================")
        print("    SISTEMA DE GESTION DE CREDENCIALES  ")
        print("========================================")
        print("1. Registrar nuevo usuario")
        print("2. Iniciar sesión")
        print("3. Cambiar contraseña")
        print("4. Ver lista de usuarios")
        print("5. Eliminar usuario")
        print("6. Salir")
        
        opcion = input("Selecciona una opción (1-6): ").strip()

        if opcion == "1":
            registrar_usuario()
        elif opcion == "2":
            iniciar_sesion()
        elif opcion == "3":
            cambiar_password()
        elif opcion == "4":
            listar_usuarios()
        elif opcion == "5":
            eliminar_usuario()
        elif opcion == "6":
            print("\nCerrando sistema. ¡Hasta luego!")
            logging.info("Sistema cerrado por el usuario.")
            break
        else:
            print("[ADVERTENCIA] Opción inválida. Selecciona un número del 1 al 6.")

if __name__ == "__main__":
    menu_principal()