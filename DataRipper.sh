DataRipper.sh
#!/bin/bash
# DataRipper.sh - Script d'extraction agressif et optimisé pour hacking éthique
# Description : Analyse des fichiers à la recherche d’informations critiques.
# Usage : ./DataRipper.sh [options] [fichier1 fichier2 ...]
# Options :
#   -o <fichier_sortie.csv>   Fichier CSV de sortie (défaut: critical_data_report.csv)
#   -d <dossier>              Dossier à analyser (défaut : répertoire courant)
#   -h                        Affiche cette aide

# Couleurs pour la sortie terminal
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Fichiers de sortie par défaut
OUTPUT_CSV="critical_data_report.csv"
OUTPUT_TXT="critical_data_report.txt"
LOG_FILE="dataripper_log.txt"
EXPLOIT_FILE="exploit_candidates.txt"
TARGET_DIR="."

# Affichage de l'aide
usage() {
    echo -e "Usage : $0 [options] [fichier1 fichier2 ...]\n"
    echo "Options :"
    echo "  -o <fichier_sortie.csv>   Fichier CSV de sortie (défaut: $OUTPUT_CSV)"
    echo "  -d <dossier>              Dossier à analyser (défaut: répertoire courant)"
    echo "  -h                        Affiche cette aide"
    exit 0
}

# Gestion des options
while getopts "o:d:h" opt; do
    case $opt in
        o) OUTPUT_CSV="$OPTARG" ;;
        d) TARGET_DIR="$OPTARG" ;;
        h) usage ;;
        *) echo -e "${RED}Option invalide.${NC}" && usage ;;
    esac
done
shift $((OPTIND-1))

# Gestion de l'interruption (Ctrl+C, SIGTERM)
trap "echo -e '\n${RED}Interruption détectée. Arrêt du script.${NC}'; exit 1" SIGINT SIGTERM

# Récupération de la liste des fichiers à analyser
if [ $# -eq 0 ]; then
    if find "$TARGET_DIR" -maxdepth 1 -type f | grep -q .; then
        mapfile -t FILES < <(find "$TARGET_DIR" -maxdepth 1 -type f -not -name "$(basename "$0")")
        echo -e "${GREEN}Aucun fichier spécifié. Analyse agressive de tous les fichiers du dossier '$TARGET_DIR': ${FILES[@]}${NC}"
    else
        echo -e "${RED}Erreur : Aucun fichier trouvé dans le dossier '$TARGET_DIR'.${NC}"
        echo "Usage : $0 [options] [fichier1 fichier2 ...]"
        exit 1
    fi
else
    FILES=("$@")
fi

# Initialisation des fichiers de sortie (écrase les précédents)
init_outputs() {
    echo "Rapport d'extraction critique - $(date)" > "$OUTPUT_TXT"
    echo "----------------------------------------" >> "$OUTPUT_TXT"
    echo "Fichier,FType,Valeur,Note" > "$OUTPUT_CSV"
    echo "Log d'analyse agressive - $(date)" > "$LOG_FILE"
    echo "Candidats à l'exploitation - $(date)" > "$EXPLOIT_FILE"
    {
        echo -e "\nAdresses IP détectées :"
        echo -e "\nMots de passe potentiels :"
        echo -e "\nHashes détectés :"
        echo -e "\nURLs détectées :"
        echo -e "\nPorts détectés :"
        echo -e "\nClés API/Tokens détectés :"
        echo -e "\nEmails détectés :"
        echo -e "\nTables/DB/Fichiers détectés :"
        echo -e "\nChaînes de connexion détectées :"
        echo -e "\nFragments SQL détectés :"
        echo -e "\nChemins de fichiers détectés :"
        echo -e "\nVariables sensibles détectées :"
    } >> "$OUTPUT_TXT"
}

init_outputs

# Fonctions d'ajout dans les rapports
add_to_report() {
    local file="$1"
    local type="$2"
    local value="$3"
    local note="$4"
    echo "$file,$type,$value,$note" >> "$OUTPUT_CSV"
    echo "[$file] $type : $value ($note)" >> "$OUTPUT_TXT"
}

log_doubtful() {
    local file="$1"
    local type="$2"
    local value="$3"
    echo "[$file] $type douteux : $value" >> "$LOG_FILE"
}

add_exploit_candidate() {
    local file="$1"
    local type="$2"
    local value="$3"
    echo "[$file] $type : $value" >> "$EXPLOIT_FILE"
}

# --- Fonctions d'extraction par catégorie ---

extract_ipv4() {
    local file="$1"
    grep -E -o "([0-9]{1,3}\.){3}[0-9]{1,3}" "$file" | sort -u | while read -r ip; do
        IFS='.' read -r -a octets <<< "$ip"
        valid=true
        for octet in "${octets[@]}"; do
            if [[ $octet -gt 255 ]]; then
                valid=false
                break
            fi
        done
        if $valid; then
            normalized_ip=$(printf "%d.%d.%d.%d" "${octets[0]}" "${octets[1]}" "${octets[2]}" "${octets[3]}")
            if [[ ${octets[0]} -eq 10 ]] || { [[ ${octets[0]} -eq 172 ]] && [[ ${octets[1]} -ge 16 && ${octets[1]} -le 31 ]]; } || { [[ ${octets[0]} -eq 192 ]] && [[ ${octets[1]} -eq 168 ]]; }; then
                note="Privée"
            else
                note="Publique"
            fi
            add_to_report "$file" "IPv4" "$normalized_ip" "$note"
            add_exploit_candidate "$file" "IP" "$normalized_ip"
        else
            log_doubtful "$file" "IPv4" "$ip"
        fi
    done
}

extract_ipv6() {
    local file="$1"
    grep -E -o "([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}" "$file" | sort -u | while read -r ip; do
        add_to_report "$file" "IPv6" "$ip" "Adresse IPv6"
        add_exploit_candidate "$file" "IPv6" "$ip"
    done
}

# Extraction des mots de passe affinée :
# - Minimum 8 caractères, au moins une majuscule, une minuscule et deux chiffres.
# - On exclut les chaînes entièrement numériques et une liste d'exclusions élargie.
extract_passwords() {
    local file="$1"
    grep -Po '\b(?=(?:.*[0-9]){2,})(?=.*[a-z])(?=.*[A-Z])[A-Za-z0-9!@#$%^&*]{8,}\b' "$file" | \
    grep -vE '^[0-9]+$' | \
    grep -vEi "DataRipper|Analyse|Rapport|mot[[:space:]]?de[[:space:]]?passe|clé|variable|SQL|control|error|text|line|header|descr|code|table|index|default|example|ADAPTEURO|ADtLivrTard|ADtLivrTot|AMELIORATION|ARCHIVAGE|ATGPFTPErr" | \
    sort -u | while read -r pass; do
        add_to_report "$file" "Mot de passe" "$pass" "Mot de passe potentiel"
        add_exploit_candidate "$file" "Password" "$pass"
    done
}

extract_hashes() {
    local file="$1"
    declare -A hash_patterns=(
        ["MD5"]="\\b[a-fA-F0-9]{32}\\b"
        ["SHA1"]="\\b[a-fA-F0-9]{40}\\b"
        ["SHA256"]="\\b[a-fA-F0-9]{64}\\b"
        ["SHA512"]="\\b[a-fA-F0-9]{128}\\b"
    )
    for hash_type in "${!hash_patterns[@]}"; do
        grep -E -o "${hash_patterns[$hash_type]}" "$file" | sort -u | while read -r hash; do
            add_to_report "$file" "$hash_type" "$hash" "Hash $hash_type"
            add_exploit_candidate "$file" "Hash" "$hash"
        done
    done
}

extract_urls() {
    local file="$1"
    grep -E -o "(https?|ftp|ldap|smb|telnet|ssh)://[a-zA-Z0-9./?=_-]+" "$file" | sort -u | while read -r url; do
        add_to_report "$file" "URL" "$url" "Lien détecté"
        add_exploit_candidate "$file" "URL" "$url"
    done
}

extract_ports() {
    local file="$1"
    grep -E -o "(:|port=)[0-9]{1,5}\\b" "$file" | sed 's/.*[:=]\([0-9]\+\)\b/\1/' | sort -u | while read -r port; do
        if [[ $port -ge 1 && $port -le 65535 ]]; then
            add_to_report "$file" "Port" "$port" "Port réseau"
            add_exploit_candidate "$file" "Port" "$port"
        fi
    done
}

extract_api_keys() {
    local file="$1"
    grep -E -o "\b[a-zA-Z0-9_-]{32,}\b" "$file" | grep -vE "^[A-Z][a-z]+[A-Z]|Control|Caption|Function|Variable|Description|Header|Line|__" | sort -u | while read -r key; do
        add_to_report "$file" "Clé API/Token" "$key" "Clé potentielle"
        add_exploit_candidate "$file" "API Key" "$key"
    done
}

extract_emails() {
    local file="$1"
    grep -E -o "\b[A-Za-z0-9._%+-]{3,}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b" "$file" | sort -u | while read -r email; do
        add_to_report "$file" "Email" "$email" "Adresse email"
        add_exploit_candidate "$file" "Email" "$email"
    done
}

extract_tables_files() {
    local file="$1"
    grep -E -o "\b(table|db|schema)[A-Za-z0-9_-]+\b|\b[A-Za-z0-9_-]+\.(txt|log|conf|ini|sql|db|dump)\b" "$file" | sort -u | while read -r item; do
        add_to_report "$file" "Table/DB/File" "$item" "Possible table, DB ou fichier"
        add_exploit_candidate "$file" "Table/DB/File" "$item"
    done
}

extract_connexion_strings() {
    local file="$1"
    grep -E -o "\b[a-zA-Z0-9._%+-]+:[a-zA-Z0-9!@#$%^&*]+@[a-zA-Z0-9.-]+(:[0-9]{1,5})?\b" "$file" | sort -u | while read -r conn; do
        add_to_report "$file" "Connexion" "$conn" "Possible chaîne de connexion"
        add_exploit_candidate "$file" "Connexion" "$conn"
    done
}

extract_sql_fragments() {
    local file="$1"
    grep -E -o "\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|FROM|WHERE|JOIN|UNION)[[:space:]]+[A-Za-z0-9_-]+\b" "$file" | sort -u | while read -r sql; do
        add_to_report "$file" "SQL" "$sql" "Fragment SQL potentiel"
        add_exploit_candidate "$file" "SQL" "$sql"
    done
}

extract_file_paths() {
    local file="$1"
    grep -E -o "\b(/|[A-Za-z]:\\)[A-Za-z0-9_/\\.-]+" "$file" | sort -u | while read -r path; do
        add_to_report "$file" "Chemin" "$path" "Chemin système potentiel"
        add_exploit_candidate "$file" "Path" "$path"
    done
}

extract_sensitive_vars() {
    local file="$1"
    grep -E -o "\b[A-Za-z0-9_]+=[A-Za-z0-9!@#$%^&*./_-]{8,}\b" "$file" | sort -u | while read -r var; do
        add_to_report "$file" "Variable" "$var" "Variable sensible potentielle"
        add_exploit_candidate "$file" "Variable" "$var"
    done
}

# Fonction principale de traitement d'un fichier
process_file() {
    local file="$1"
    if [ ! -r "$file" ]; then
        echo -e "${RED}Impossible de lire le fichier $file, il sera ignoré.${NC}"
        return
    fi
    echo -e "${GREEN}Analyse agressive de $file...${NC}"
    extract_ipv4 "$file"
    extract_ipv6 "$file"
    extract_passwords "$file"
    extract_hashes "$file"
    extract_urls "$file"
    extract_ports "$file"
    extract_api_keys "$file"
    extract_emails "$file"
    extract_tables_files "$file"
    extract_connexion_strings "$file"
    extract_sql_fragments "$file"
    extract_file_paths "$file"
    extract_sensitive_vars "$file"
}

# Parcours et analyse de chaque fichier
for file in "${FILES[@]}"; do
    if [ -f "$file" ]; then
        process_file "$file"
    else
        echo -e "${RED}Avertissement : Le fichier $file n'existe pas ou n'est pas un fichier régulier, ignoré.${NC}"
    fi
done

# Statistiques finales : comptage par type dans le CSV
{
    echo -e "\nRésumé :"
    for type in "IPv4" "IPv6" "Mot de passe" "MD5" "SHA1" "SHA256" "SHA512" "URL" "Port" "Clé API/Token" "Email" "Table/DB/File" "Connexion" "SQL" "Chemin" "Variable"; do
        count=$(grep -c ",$type," "$OUTPUT_CSV")
        echo "$type trouvés : $count"
    done
} >> "$OUTPUT_TXT"

echo -e "${GREEN}Analyse agressive terminée.${NC}"
echo "Résultats disponibles dans :"
echo "- $OUTPUT_TXT (rapport lisible)"
echo "- $OUTPUT_CSV (CSV pour analyse)"
echo "- $EXPLOIT_FILE (candidats à l'exploitation)"
echo "Log des cas douteux dans : $LOG_FILE"

# Restriction des permissions sur les fichiers de sortie
chmod 600 "$OUTPUT_TXT" "$OUTPUT_CSV" "$LOG_FILE" "$EXPLOIT_FILE"
