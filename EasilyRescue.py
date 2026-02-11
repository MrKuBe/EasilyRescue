"""
EasilyRescue - Outil de continuité d'activité pour le DPI Easily.

Auteur/Designer: Bertrand Kuzbinski

Cette application met en oeuvre la procédure de continuité d'activité (PCA) en cas
d'indisponibilité du logiciel de dossier patient informatisé (DPI) "Easily",
édité par les Hospices Civils de Lyon (HCL).

Elle automatise la récupération, la décompression et l'indexation de lots de
fichiers depuis un serveur SFTP et génère un rapport HTML interactif pour
consulter les documents patients.

Fonctionnalités principales:
- Chargement de la configuration depuis un fichier JSONC (avec commentaires).
- Connexion à un serveur SFTP avec support de mot de passe ou de clé privée.
- Téléchargement parallèle des archives ZIP pour plusieurs secteurs.
- Vérification de l'intégrité des fichiers téléchargés via checksum (SHA256).
- Mode "téléchargement propre" : utilise un cache temporaire pour garantir une
  mise à jour atomique et sécurisée des données locales.
- Décompression parallèle des archives.
- Suppression optionnelle des archives après décompression.
- Génération d'un rapport HTML unique (index.html) avec :
  - Tableau de recherche, de tri et de filtrage dynamique.
  - Affichage des métadonnées (taille, date, type, etc.).
  - Statistiques de l'exécution (temps, bande passante, version).
- Journalisation (logging) détaillée dans la console et dans un fichier.

Historique des versions:
- v1.0.6beta (2025-10-24): Ajout d'un cartouche de documentation et passage en bêta.
- v1.0.5beta (2025-10-24): Version initiale avec parallélisation, checksum, et UI améliorée.
"""
import json  # Pour la manipulation des données au format JSON (lecture de la configuration).
import re  # Pour les expressions régulières (nettoyage des commentaires du fichier JSONC).
import logging  # Pour la journalisation des événements, erreurs et informations.
from pathlib import Path  # Pour une manipulation orientée objet et multi-plateforme des chemins de fichiers.
from typing import Dict, Any, List  # Pour l'annotation des types, améliorant la lisibilité et la robustesse du code.
import zipfile  # Pour la décompression des archives .zip.
from datetime import date, datetime  # Pour la manipulation des dates et heures (timestamps, nom des logs).
import os  # Pour interagir avec le système d'exploitation (chemins de fichiers, variables d'environnement).
import time  # Pour mesurer les temps d'exécution.
import hashlib  # Pour calculer les sommes de contrôle (checksums) des fichiers (SHA256).
from concurrent.futures import ThreadPoolExecutor, as_completed  # Pour gérer l'exécution parallèle des tâches (téléchargement, décompression).
import tempfile  # Pour créer des dossiers et fichiers temporaires de manière sécurisée.
import shutil  # Pour les opérations de haut niveau sur les fichiers et dossiers (suppression, déplacement).
import sys  # Pour interagir avec l'interpréteur Python (arguments de la ligne de commande, sortie standard).
import paramiko  # Pour l'implémentation du protocole SFTP (connexion et transfert de fichiers).
from tqdm import tqdm  # Pour afficher des barres de progression intelligentes et esthétiques.
import webbrowser  # Pour ouvrir automatiquement le rapport HTML dans le navigateur par défaut.
import html  # Pour l'échappement des caractères spéciaux dans la génération du rapport HTML.

# Constantes
CONFIG_FILENAME = "config.jsonc"


class ConfigManager:
    """Classe pour charger et gérer la configuration depuis un fichier JSONC."""

    def __init__(self, config_filename: str = CONFIG_FILENAME):
        self.project_root = Path(__file__).resolve().parent
        self.config_path = self.project_root / config_filename
        self._config_data = self._load()

    def _strip_block_comments(self, text: str) -> str:
        return re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)

    def _strip_line_comments_preserving_strings(self, text: str) -> str:
        def strip_line(line: str) -> str:
            in_string, escaped = False, False
            for i, ch in enumerate(line):
                if ch == "\\" and not escaped:
                    escaped = True
                    continue
                if ch == '"' and not escaped:
                    in_string = not in_string
                if not in_string and ch == "/" and i + 1 < len(line) and line[i + 1] == "/":
                    return line[:i]
                escaped = False
            return line
        return "\n".join(strip_line(l) for l in text.splitlines())

    def _load(self) -> Dict[str, Any]:
        if not self.config_path.exists():
            raise FileNotFoundError(f"Fichier de configuration introuvable: {self.config_path}")
        raw = self.config_path.read_text(encoding="utf-8")
        without_blocks = self._strip_block_comments(raw)
        without_line_comments = self._strip_line_comments_preserving_strings(without_blocks)
        return json.loads(without_line_comments)

    def get(self, key: str, default: Any = None) -> Any:
        """Récupère une valeur de la config, avec support des clés imbriquées (ex: 'sftp.hostname')."""
        keys = key.split('.')
        value = self._config_data
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        return value

    @property
    def root_folder(self) -> Path:
        """Résout et retourne le chemin absolu du dossier racine des données."""
        root_folder_value = str(self.get("rootFolder", "data"))
        path_from_config = Path(root_folder_value.strip())

        if path_from_config.is_absolute():
            return path_from_config.resolve()
        else:
            return (self.project_root / path_from_config.as_posix().lstrip('/')).resolve()

# Instance unique du gestionnaire de configuration
config = ConfigManager()


def setup_logging(log_path: Path) -> None:
    """Configure un logger simple vers un fichier avec timestamps."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Obtenir le logger racine
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    
    # Créer un formateur commun
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    
    # Configurer le handler pour le fichier, en forçant l'encodage UTF-8
    file_handler = logging.FileHandler(log_path, encoding="utf-8-sig")
    file_handler.setFormatter(formatter)
    
    # Configurer le handler pour la console, en forçant aussi l'encodage UTF-8
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    
    # Ajouter les handlers au logger racine
    root_logger.handlers = [file_handler, stream_handler]

def find_zip_files(dir_path: Path, code: str) -> List[Path]:
    """Retourne les archives zip du type 'CODE_*.zip' dans dir_path."""
    pattern = f"{code}_*.zip"
    return sorted(dir_path.glob(pattern))


def unzip_archive(zip_path: Path, destination: Path) -> bool:
    """Décompresse une archive zip dans le dossier destination avec une barre de progression."""
    with zipfile.ZipFile(zip_path, "r") as zf:
        # Itérer sur les fichiers de l'archive pour afficher une progression
        for member in tqdm(zf.infolist(), desc=f'  Décompresse {zip_path.name}', unit='fichiers', leave=False):
            zf.extract(member, destination)
    logging.info(f"Archive {zip_path.name} décompressée avec succès.")
    return True

def process_code_folder(root_folder: Path, code: str, delete_zip: bool) -> None:
    """Vérifie le dossier pour `code`, trouve les zips correspondants et les décompresse."""
    target_dir = root_folder / code
    if not target_dir.exists() or not target_dir.is_dir():
        logging.warning(f"Dossier manquant pour {code}: {target_dir}")
        return
    logging.info(f"Dossier trouvé pour {code}: {target_dir}")

    zips = find_zip_files(target_dir, code)
    if not zips:
        logging.warning(f"Aucune archive trouvée pour {code} dans {target_dir}")
        return

    for zip_path in tqdm(zips, desc=f'Traitement des zips pour {code}', unit='archive', leave=False):
        logging.info(f"Traitement de l'archive: {zip_path}")
        try:
            success = unzip_archive(zip_path, target_dir)
            if success:
                if delete_zip:
                    try:
                        zip_path.unlink()
                        logging.info(f"Archive supprimée: {zip_path}")
                    except Exception as exc_delete:
                        logging.error(f"Erreur lors de la suppression de l'archive {zip_path}: {exc_delete}")
        except Exception as exc:
            logging.exception(f"Erreur lors de la décompression de {zip_path}: {exc}")


def get_remote_file_hash(transport: paramiko.Transport, remote_path: str) -> str | None:
    """Exécute 'sha256sum' sur le serveur distant pour obtenir le hash d'un fichier."""
    # Liste des commandes à essayer, de la plus courante à la moins courante.
    commands_to_try = [
        ("sha256sum", "sha256sum '{path}'", 0),  # sha256sum output: <hash>  <filename>
        ("openssl", "openssl dgst -sha256 '{path}'", 1) # openssl output: SHA256(<path>)= <hash>
    ]

    for name, command_template, hash_pos in commands_to_try:
        try:
            channel = transport.open_session()
            command = command_template.format(path=remote_path)
            logging.info(f"Tentative de calcul du hash distant avec '{name}' pour '{remote_path}'")
            channel.exec_command(command)
            exit_status = channel.recv_exit_status()

            if exit_status == 0:
                output = channel.makefile('r', -1).read().strip()
                # L'output de openssl est "SHA256(path)= hash", on prend le dernier élément.
                # L'output de sha256sum est "hash  path", on prend le premier.
                remote_hash = output.split()[hash_pos]
                logging.info(f"Calcul du hash avec '{name}' réussi.")
                return remote_hash
            else:
                stderr_output = channel.makefile_stderr('r', -1).read()
                logging.warning(f"La commande '{name}' a échoué (code: {exit_status}). Erreur: {stderr_output.strip()}")
                continue # Essayer la commande suivante
        except Exception as e:
            logging.error(f"Exception lors de l'exécution de '{name}' pour le hash distant: {e}")
            continue

    logging.error(f"Toutes les méthodes pour calculer le hash distant de '{remote_path}' ont échoué.")
    return None


def get_local_file_hash(file_path: Path, algorithm: str = 'sha256') -> str:
    """Calcule le hash d'un fichier local."""
    h = hashlib.new(algorithm)
    with open(file_path, 'rb') as f:
        # Lire le fichier par blocs pour gérer les gros fichiers
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


def download_files_for_code_sftp(sftp_config: Dict[str, Any], local_root: Path, code: str) -> tuple[bool, int]:
    """Télécharge les fichiers zip pour un code spécifique et retourne (succès, octets_téléchargés)."""
    if not sftp_config.get("enabled"):
        # This check is now redundant if called correctly, but safe to keep.
        return True, 0

    logging.info(f"[{code}] Démarrage du téléchargement SFTP.")
    # Note de sécurité : La désactivation de la vérification de la clé d'hôte
    # est un risque en production (attaque "man-in-the-middle").
    # Pour une meilleure sécurité, il faudrait charger les clés connues.
    # Pour l'instant, nous continuons sans pour la simplicité.
    # transport.load_host_keys(os.path.expanduser('~/.ssh/known_hosts'))
    if not sftp_config.get("verify_host_key", False):
        logging.warning("La vérification de la clé d'hôte SFTP est désactivée. C'est un risque de sécurité en production.")

    host = sftp_config["hostname"]
    port = sftp_config.get("port", 22)
    user = sftp_config["username"]
    pwd = sftp_config.get("password")
    key_path = sftp_config.get("private_key_path")
    if key_path:
        key_path = os.path.expanduser(key_path) # Gère les chemins comme ~/.ssh/id_rsa
        logging.info(f"Chemin de la clé privée SFTP résolu : {key_path}")
    else:
        logging.info("Aucun chemin de clé privée SFTP n'est configuré.")


    try:
        transport = paramiko.Transport((host, port))
        
        # Connexion avec clé privée ou mot de passe
        if key_path and os.path.exists(key_path):
            logging.info(f"Tentative de connexion avec la clé privée: {key_path}")
            pkey = paramiko.Ed25519Key.from_private_key_file(key_path) # ou RSAKey, etc.
            transport.connect(username=user, pkey=pkey)
        else:
            logging.info("Tentative de connexion avec mot de passe.")
            transport.connect(username=user, password=pwd)

        with paramiko.SFTPClient.from_transport(transport) as sftp:
            logging.info(f"Connecté à {user}@{host}")
            
            initial_cwd = sftp.getcwd()
            logging.info(f"Dossier de travail initial sur le serveur SFTP : '{initial_cwd}'")
            try:
                logging.info("Contenu du dossier de travail initial :")
                for item in sftp.listdir('.'):
                    logging.info(f"  - {item}")
            except Exception as e:
                logging.warning(f"Impossible de lister le contenu du dossier initial : {e}")

            remote_dir = sftp_config["remote_dir"]
            try:
                sftp.chdir(remote_dir)
                logging.info(f"Dossier distant actuel: {sftp.getcwd()}")
                try:
                    logging.info(f"Contenu du dossier distant '{sftp.getcwd()}' :")
                    # Lister les 20 premiers éléments pour ne pas surcharger les logs
                    for i, item in enumerate(sftp.listdir('.')):
                        logging.info(f"  - {item}")
                except Exception as e:
                    logging.warning(f"Impossible de lister le contenu du dossier distant : {e}")
            except IOError:
                logging.critical(f"Le dossier distant '{remote_dir}' n'existe pas ou est inaccessible.")
                logging.info("Pistes de débogage possibles :")
                logging.info(f"1. Le chemin '{remote_dir}' est-il correct par rapport au dossier initial '{initial_cwd}' ? Parfois, il ne faut pas mettre de '/' au début (ex: 'ftp_data/CHUGA' au lieu de '/ftp_data/CHUGA').")
                logging.info(f"2. L'utilisateur SFTP '{user}' a-t-il les permissions nécessaires pour accéder à ce dossier ?")
                logging.info("3. Vérifiez qu'il n'y a pas de faute de frappe dans le nom du dossier dans votre fichier config.jsonc.")
                return False, 0

            # Garder en mémoire le répertoire de base des secteurs
            base_remote_dir = sftp.getcwd()

            pattern = f"{code}_*.zip"
            total_bytes_downloaded = 0
            local_dir = local_root / code
            local_dir.mkdir(parents=True, exist_ok=True)

            try:
                # Se déplacer dans le sous-dossier du code
                sftp.chdir(code)
                logging.info(f"[{code}] Recherche des archives dans : {sftp.getcwd()}")

                remote_files = [f for f in sftp.listdir() if f.startswith(code) and f.endswith('.zip')]
                if not remote_files:
                    logging.error(f"[{code}] Aucune archive distante trouvée dans '{sftp.getcwd()}'.")
                    logging.info(f"  -> Assurez-vous que les archives '{pattern}' existent bien dans ce dossier.")
                    return True, 0 # Pas une erreur fatale, on continue

                for filename in tqdm(remote_files, desc=f'DL {code}', unit='fichier', leave=True):
                    remote_path = f"{sftp.getcwd()}/{filename}"
                    local_path = local_dir / filename

                    # 1. Obtenir le hash distant AVANT le téléchargement
                    remote_hash = get_remote_file_hash(transport, remote_path)
                    if remote_hash:
                        logging.info(f"[{code}] Hash distant (SHA256) pour {filename}: {remote_hash[:12]}...")
                    else:
                        logging.warning(f"[{code}] Impossible d'obtenir le hash distant pour {filename}. La vérification d'intégrité sera sautée.")

                    # 2. Télécharger le fichier
                    file_size = sftp.stat(filename).st_size
                    with tqdm(total=file_size, unit='B', unit_scale=True, desc=f'  {filename}', leave=False) as pbar:
                        sftp.get(filename, str(local_path), callback=lambda sent, total: pbar.update(sent - pbar.n))

                    if pbar.n < file_size:
                        pbar.update(file_size - pbar.n)

                    # 3. Vérifier le hash local APRÈS le téléchargement
                    if remote_hash:
                        local_hash = get_local_file_hash(local_path)
                        if local_hash == remote_hash:
                            logging.info(f"[{code}] Intégrité VÉRIFIÉE pour {filename}.")
                        else:
                            logging.critical(f"[{code}] CORRUPTION DE FICHIER DÉTECTÉE pour {filename} !")
                            logging.error(f"  -> Hash distant: {remote_hash}\n  -> Hash local  : {local_hash}")
                            local_path.unlink() # Supprimer le fichier corrompu
                            return False, total_bytes_downloaded # Signaler un échec critique pour ce code
                    else:
                        logging.info(f"[{code}] Téléchargement terminé (sans vérification d'intégrité): {filename}")
                    total_bytes_downloaded += file_size

            except IOError:
                logging.error(f"[{code}] Le sous-dossier est introuvable sur le serveur à l'emplacement '{base_remote_dir}/{code}'.")
                return False, 0 # C'est une erreur de configuration probable
            finally:
                # Revenir au dossier de base pour la prochaine itération
                sftp.chdir(base_remote_dir)

    except Exception as exc:
        logging.critical(f"[{code}] Échec du prérequis SFTP. Erreur: {exc}")
        return False, 0

    return True, total_bytes_downloaded

def run_processing() -> None:
    """Orchestre le traitement complet : téléchargement, décompression et génération du rapport."""
    start_time_total = time.monotonic()
    root_folder = config.root_folder
    codes: List[str] = config.get("data2Download", [])
    
    # Log des chemins résolus pour le débogage
    logging.info(f"Chemin racine des données résolu : {root_folder}")
    
    if not root_folder.exists():
        logging.warning(f"Le dossier racine n'existe pas, création: {root_folder}")
        root_folder.mkdir(parents=True, exist_ok=True)
    
    # Étape 1: Téléchargement SFTP si activé
    sftp_config = config.get("sftp", {})
    clean_before_download = config.get("settings.clean_before_download", False)
    duration_dl = 0.0
    bandwidth_mbps = 0.0
    
    download_target_folder = root_folder
    temp_dir_handle = None

    if sftp_config.get("enabled", False):
        if clean_before_download:
            # Créer un dossier temporaire sécurisé pour le téléchargement
            temp_dir_handle = tempfile.TemporaryDirectory(prefix="easilysecours_dl_")
            download_target_folder = Path(temp_dir_handle.name)
            logging.info(f"Mode 'clean' activé. Utilisation du dossier temporaire : {download_target_folder}")

        start_time_dl = time.monotonic()
        total_bytes_downloaded = 0
        all_downloads_successful = True
        logging.info("Étape 1: Téléchargement SFTP en parallèle...")
        with ThreadPoolExecutor(max_workers=4) as executor:
            # Soumettre une tâche de téléchargement pour chaque code
            future_to_code = {executor.submit(download_files_for_code_sftp, sftp_config, download_target_folder, code): code for code in codes}
            for future in tqdm(as_completed(future_to_code), total=len(codes), desc="Téléchargement global"):
                code = future_to_code[future]
                try:
                    success, bytes_downloaded = future.result()
                    total_bytes_downloaded += bytes_downloaded
                    if not success:
                        all_downloads_successful = False
                        logging.error(f"Le téléchargement a échoué pour le code {code}. Voir les logs pour les détails.")
                except Exception as exc:
                    all_downloads_successful = False
                    logging.error(f"Une exception est survenue lors du téléchargement pour {code}: {exc}")
        duration_dl = time.monotonic() - start_time_dl
        logging.info(f"Temps total de téléchargement : {duration_dl:.2f} secondes.")
        if duration_dl > 0:
            # (octets * 8) / (secondes * 1024 * 1024) = Mbps
            bandwidth_mbps = (total_bytes_downloaded * 8) / (duration_dl * 1024 * 1024)
            logging.info(f"Bande passante moyenne estimée : {bandwidth_mbps:.2f} Mbps.")

        if clean_before_download and temp_dir_handle:
            if all_downloads_successful:
                logging.info("Tous les téléchargements ont réussi. Remplacement des données locales.")
                for code in codes:
                    # Supprimer l'ancien dossier
                    old_path = root_folder / code
                    if old_path.exists():
                        logging.info(f"Suppression de l'ancien dossier : {old_path}")
                        shutil.rmtree(old_path)
                    # Déplacer le nouveau dossier
                    new_path = download_target_folder / code
                    if new_path.exists():
                        logging.info(f"Déplacement de {new_path} vers {root_folder}")
                        shutil.move(str(new_path), str(root_folder))
            else:
                logging.critical("Échec d'un ou plusieurs téléchargements. Les données locales n'ont PAS été modifiées.")
            
            # Le dossier temporaire est automatiquement supprimé à la sortie du bloc `with`
            logging.info(f"Nettoyage du dossier temporaire.")
            temp_dir_handle.cleanup()

    else:
        logging.info("Étape 1: Téléchargement SFTP désactivé.")

    # Étape 2: Décompression des archives
    logging.info("Étape 2: Décompression des archives en parallèle...")
    start_time_unzip = time.monotonic()
    delete_zip = config.get("settings.delete_zip_after_unzip", False)
    with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
        future_to_code = {executor.submit(process_code_folder, root_folder, code, delete_zip): code for code in codes}
        for future in tqdm(as_completed(future_to_code), total=len(codes), desc="Décompression globale"):
            code = future_to_code[future]
            try:
                future.result() # On récupère le résultat pour propager les exceptions
            except Exception as exc:
                logging.error(f"Une exception est survenue lors de la décompression pour {code}: {exc}")
    duration_unzip = time.monotonic() - start_time_unzip
    logging.info(f"Temps total de décompression : {duration_unzip:.2f} secondes.")

    # Étape 3: Génération de l'index HTML
    logging.info("Étape 3: Génération de l'index HTML...")
    try:
        entries: List[Dict[str, Any]] = scan_unzipped_files(root_folder, codes) # type: ignore
        generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        app_version = config.get("version", "")
        index_path = generate_html_index(entries, root_folder, generated_at, duration_dl, duration_unzip, bandwidth_mbps, app_version)
        
        # Affiche un lien cliquable vers le rapport dans le terminal
        logging.info(f"Index HTML généré: \x1B]8;;{index_path.as_uri()}\x07{index_path}\x1B]8;;\x07")
        
        # Tenter d'ouvrir le fichier HTML dans le navigateur par défaut de l'utilisateur.
        try:
            webbrowser.open(index_path.as_uri())
            logging.info("Ouverture du rapport HTML dans le navigateur par défaut.")
        except Exception as exc:
            logging.warning(f"Impossible d'ouvrir automatiquement le rapport dans le navigateur: {exc}")
            logging.info(f"Vous pouvez l'ouvrir manuellement ici : \x1B]8;;{index_path.as_uri()}\x07{index_path.as_uri()}\x1B]8;;\x07")
    except Exception as exc:
        logging.exception(f"Erreur lors de la génération de l'index HTML: {exc}")
    
    duration_total = time.monotonic() - start_time_total
    logging.info(f"Temps de traitement total : {duration_total:.2f} secondes.")


def scan_unzipped_files(root_folder: Path, codes: List[str]) -> List[Dict[str, Any]]:
    """Parcourt les dossiers des codes et liste tous les fichiers (hors .zip)."""
    logging.info("Scan des fichiers dézippés pour l'index HTML")
    entries: List[Dict[str, Any]] = []
    for code in codes:
        base = root_folder / code
        if not base.is_dir():
            logging.debug(f"Dossier ignoré (absent): {base}")
            continue
        for file_path in base.rglob('*'):
            if not file_path.is_file():
                continue
            if file_path.suffix.lower() == '.zip':
                continue
            try:
                stat = file_path.stat()
                size_bytes = stat.st_size
                mtime = datetime.fromtimestamp(stat.st_mtime)
                rel_to_root = file_path.relative_to(root_folder).as_posix()
                # doc_type = premier dossier après le code (ex: SLP7031/DocType/....)
                parts = rel_to_root.split('/')
                doc_type = parts[1] if len(parts) >= 2 else ''
                entries.append({
                    'code': code,
                    'name': file_path.name,
                    'rel_path': rel_to_root,
                    'size_bytes': size_bytes,
                    'modified': mtime.isoformat(timespec='seconds'),
                    'ext': file_path.suffix.lower().lstrip('.'),
                    'abs_path': str(file_path),
                    'doc_type': doc_type,
                })
            except Exception as exc:
                logging.exception(f"Erreur de lecture du fichier {file_path}: {exc}")
    logging.info(f"Total fichiers indexés: {len(entries)}")
    return entries


def generate_html_index(entries: List[Dict[str, Any]], root_folder: Path, generated_at: str, duration_dl: float, duration_unzip: float, bandwidth_mbps: float, app_version: str) -> Path:
    """Génère un index HTML Fomantic UI listant les fichiers, avec recherche et tri."""
    project_root = Path(__file__).resolve().parent
    index_path = project_root / 'index.html'

    # Construire lignes de tableau et calculer href relatifs depuis la racine du projet
    rows_html: List[str] = []
    codes_set = set()
    doc_types_set = set()
    for e in entries:
        file_path = root_folder / e['rel_path']
        try:
            href = file_path.relative_to(project_root).as_posix()
        except Exception:
            href = file_path.as_uri() if file_path.exists() else file_path.as_posix()
        code_esc = html.escape(e['code'])
        doc_esc = html.escape(e.get('doc_type', ''))
        ext_esc = html.escape(e['ext'])
        name_esc = html.escape(e['name'])
        rows_html.append(
            f"<tr data-code=\"{code_esc}\" data-doc=\"{doc_esc}\">"
            f"<td>{code_esc}</td>"
            f"<td><a href=\"{html.escape(href)}\" target=\"_blank\">{name_esc}</a></td>"
            f"<td>{doc_esc}</td>"
            f"<td>{ext_esc}</td>"
            f"<td data-bytes=\"{e['size_bytes']}\">{_format_size(e['size_bytes'])}</td>"
            f"<td>{html.escape(e['modified'])}</td>"
            f"<td class=\"collapsing\"><a href=\"{html.escape(href)}\" target=\"_blank\" class=\"ui tiny button\">Ouvrir</a></td>"
            f"</tr>"
        )
        if e['code']:
            codes_set.add(e['code'])
        if e.get('doc_type'):
            doc_types_set.add(e.get('doc_type') or '')

    sector_count = len(codes_set)
    doc_types_list = sorted([d for d in doc_types_set if d])
    html_content = _build_fomantic_html('\n'.join(rows_html), generated_at, sector_count, doc_types_list, len(entries), duration_dl, duration_unzip, bandwidth_mbps, app_version)
    index_path.write_text(html_content, encoding='utf-8')
    return index_path


def _format_size(num_bytes: int) -> str:
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    size = float(num_bytes)
    for unit in units:
        if size < 1024.0 or unit == units[-1]:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} TB"


def _build_fomantic_html(rows: str, generated_at: str, sector_count: int, doc_types_list: List[str], file_count: int, duration_dl: float, duration_unzip: float, bandwidth_mbps: float, app_version: str) -> str:
    # Fomantic UI via CDN et JS de recherche/tri
    html_tpl = """<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>EasilyRescue - Index des fichiers</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/fomantic-ui@2.9.3/dist/semantic.min.css">
  <style>
    body { padding: 2rem; }
    .table-container { overflow: auto; }
    .ui.table thead th { cursor: pointer; }
  </style>
</head>
<body>
  <div class="ui container">
    <h2 class="ui header">EasilyRescue __APP_VERSION__ - Index des fichiers
      <div class="sub header">Généré le __GENERATED_AT__ — Fichiers: __FILE_COUNT__ — Secteurs: __SECTOR_COUNT__ — Types: __DOC_TYPES__<br>Temps de récupération: __DL_TIME__s (Bande passante: __BANDWIDTH__ Mbps) — Temps de décompression: __UNZIP_TIME__s</div>
    </h2>
    <div class="ui segment">
      <div class="ui form" style="margin-bottom: 1rem;">
        <div class="fields" id="filterFields"></div>
      </div>
      <div class="ui grid">
        <div class="twelve wide column">
          <div class="ui icon input" style="width: 100%;">
            <input type="text" id="searchInput" placeholder="Rechercher...">
            <i class="search icon"></i>
          </div>
        </div>
        <div class="four wide right aligned column">
          <button id="resetFilters" class="ui button" type="button">Réinitialiser</button>
        </div>
      </div>
    </div>
    <div class="table-container">
      <table id="filesTable" class="ui celled striped compact table">
        <thead>
          <tr>
            <th data-key="code">Code</th>
            <th data-key="name">Nom</th>
            <th data-key="doc_type">Type</th>
            <th data-key="ext">Extension</th>
            <th data-key="size">Taille</th>
            <th data-key="modified">Modifié</th>
            <th class="collapsing">Action</th>
          </tr>
        </thead>
        <tbody>
__ROWS__
        </tbody>
      </table>
    </div>
  </div>
  <script src="https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/fomantic-ui@2.9.3/dist/semantic.min.js"></script>
  <script>
    (function(){
      const table = document.getElementById('filesTable');
      const tbody = table.querySelector('tbody');
      const searchInput = document.getElementById('searchInput');
      let sortState = { key: null, dir: 1 };
      const resetBtn = document.getElementById('resetFilters');

      function getCellValue(row, index) {
        const cell = row.children[index];
        if (index === 4) { // Index de la colonne 'Taille'
          const bytes = cell.getAttribute('data-bytes');
          return bytes ? parseInt(bytes, 10) : 0;
        }
        return cell.textContent.trim().toLowerCase();
      }

      function sortByKey(key){
        const headCells = table.querySelectorAll('thead th[data-key]');
        let index = 0;
        headCells.forEach((th, i) => { if (th.getAttribute('data-key') === key) index = i; th.classList.remove('sorted', 'ascending', 'descending'); });
        if (sortState.key === key) { sortState.dir *= -1; } else { sortState.key = key; sortState.dir = 1; }
        const rows = Array.from(tbody.querySelectorAll('tr'))
          .sort((a,b) => { const va = getCellValue(a, index); const vb = getCellValue(b, index); if (va < vb) return -1*sortState.dir; if (va > vb) return 1*sortState.dir; return 0; });
        rows.forEach(r => tbody.appendChild(r));
        const activeTh = table.querySelector('thead th[data-key="' + key + '"]');
        activeTh.classList.add('sorted', sortState.dir === 1 ? 'ascending' : 'descending');
      }

      function filterRows(){
        const t = (searchInput.value || '').toLowerCase();
        const c = (document.getElementById('filterCode') || { value: '' }).value || '';
        const d = (document.getElementById('filterDoc') || { value: '' }).value || '';
        Array.from(tbody.querySelectorAll('tr')).forEach(tr => {
          const text = tr.textContent.toLowerCase();
          const code = tr.getAttribute('data-code') || '';
          const doc = tr.getAttribute('data-doc') || '';
          const matchText = text.includes(t);
          const matchCode = !c || code === c;
          const matchDoc = !d || doc === d;
          tr.style.display = (matchText && matchCode && matchDoc) ? '' : 'none';
        });
      }

      table.querySelectorAll('thead th[data-key]').forEach(th => th.addEventListener('click', () => sortByKey(th.getAttribute('data-key'))));
      searchInput.addEventListener('input', () => filterRows());
      if (resetBtn) {
        resetBtn.addEventListener('click', () => {
          searchInput.value = '';
          const codeSel = document.getElementById('filterCode');
          const docSel = document.getElementById('filterDoc');
          if (codeSel) codeSel.value = '';
          if (docSel) docSel.value = '';
          filterRows();
        });
      }
      // Peupler dynamiquement les combos
      (function fillCombos(){
        const codes = new Set();
        const docs = new Set();
        Array.from(tbody.querySelectorAll('tr')).forEach(tr => {
          const c = tr.getAttribute('data-code') || '';
          const d = tr.getAttribute('data-doc') || '';
          if (c) codes.add(c);
          if (d) docs.add(d);
        });
        const codeSel = document.createElement('select');
        codeSel.id = 'filterCode'; codeSel.className = 'ui dropdown';
        codeSel.innerHTML = '<option value="">Tous</option>' + Array.from(codes).sort().map(c => `<option value="${c}">${c}</option>`).join('');
        const docSel = document.createElement('select');
        docSel.id = 'filterDoc'; docSel.className = 'ui dropdown';
        docSel.innerHTML = '<option value="">Tous</option>' + Array.from(docs).sort().map(d => `<option value="${d}">${d}</option>`).join('');
        const fields = document.getElementById('filterFields');
        if (fields){
          const codeField = document.createElement('div'); codeField.className = 'six wide field';
          const codeLbl = document.createElement('label'); codeLbl.textContent = 'Secteur (SLP)';
          codeField.appendChild(codeLbl); codeField.appendChild(codeSel);
          const docField = document.createElement('div'); docField.className = 'six wide field';
          const docLbl = document.createElement('label'); docLbl.textContent = 'Type de document';
          docField.appendChild(docLbl); docField.appendChild(docSel);
          fields.appendChild(codeField); fields.appendChild(docField);
          if (window.$ && $.fn.dropdown) { $('.ui.dropdown').dropdown(); }
          codeSel.addEventListener('change', () => filterRows());
          docSel.addEventListener('change', () => filterRows());
        }
      })();
    })();
  </script>
</body>
</html>
"""
    dl_time_str = f"{duration_dl:.2f}" if duration_dl > 0.01 else "N/A" # type: ignore
    bandwidth_str = f"{bandwidth_mbps:.2f}" if bandwidth_mbps > 0 else "N/A"
    doc_types_text = ", ".join(sorted([html.escape(d) for d in doc_types_list])) if doc_types_list else "Aucun"
    version_str = f"v{app_version}" if app_version else ""
    return (
        html_tpl
        .replace("__APP_VERSION__", version_str)
        .replace("__GENERATED_AT__", html.escape(generated_at))
        .replace("__SECTOR_COUNT__", str(sector_count))
        .replace("__FILE_COUNT__", f"{file_count:,}".replace(",", " "))
        .replace("__DL_TIME__", dl_time_str)
        .replace("__BANDWIDTH__", bandwidth_str)
        .replace("__UNZIP_TIME__", f"{duration_unzip:.2f}")
        .replace("__DOC_TYPES__", doc_types_text)
        .replace("__ROWS__", rows)
    )


def main() -> None:
    # Configuration du logging
    project_root = Path(__file__).resolve().parent
    logs_dir = project_root / "logs"
    script_name = Path(__file__).stem
    today_str = date.today().strftime("%Y_%m_%d")
    log_file = logs_dir / f"{script_name}_{today_str}.log"
    setup_logging(log_file)

    logging.info(f"Démarrage de l'application '{config.get('name', 'EasilySecours')}' v{config.get('version', 'N/A')}")
    
    config_full_path = config.config_path.resolve()
    logging.info(f"Chemin du fichier de configuration résolu : {config_full_path}")
    
    logging.info(f"Arguments de la ligne de commande: {sys.argv}")

    # Traitement principal
    run_processing()
    


if __name__ == "__main__":
    main()
