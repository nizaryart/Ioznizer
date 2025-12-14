\documentclass[12pt,a4paper]{article}

% ============================================
% PAQUETS ESSENTIELS
% ============================================
\usepackage[utf8]{inputenc}
\usepackage[T1]{fontenc}
\usepackage[french]{babel}
\usepackage{times} % Times New Roman
\usepackage{geometry}
\usepackage{fancyhdr}
\usepackage{titlesec}
\usepackage{tocloft}
\usepackage{graphicx}
\usepackage{xcolor}
\usepackage{booktabs}
\usepackage{array}
\usepackage{longtable}
\usepackage{amsmath}
\usepackage{float}
\usepackage{caption}
\usepackage{enumitem}
\usepackage{url}
\usepackage{listings}
\usepackage{hyperref}

% ============================================
% CONFIGURATION DES MARGES
% ============================================
\geometry{
    left=2.5cm,
    right=2.5cm,
    top=2.5cm,
    bottom=2.5cm,
    headheight=15pt
}

% ============================================
% CONFIGURATION DE LA MISE EN PAGE
% ============================================
\setlength{\parindent}{1cm}
\setlength{\parskip}{0.5cm}
\renewcommand{\baselinestretch}{1.5} % Interligne 1.5

% ============================================
% EN-TÊTES ET PIEDS DE PAGE
% ============================================
\pagestyle{fancy}
\fancyhf{}
\fancyhead[L]{\small\textit{IoZnIzEr - Analyseur de Malware avec LLM}}
\fancyhead[R]{\small\textit{Rapport de Projet}}
\fancyfoot[C]{\thepage}
\renewcommand{\headrulewidth}{0.4pt}
\renewcommand{\footrulewidth}{0pt}

% ============================================
% CONFIGURATION DES TITRES
% ============================================
\titleformat{\section}
{\Large\bfseries\centering}
{\thesection}{1em}{}
[\titlerule]

\titleformat{\subsection}
{\large\bfseries}
{\thesubsection}{1em}{}

\titleformat{\subsubsection}
{\normalsize\bfseries}
{\thesubsubsection}{1em}{}

% ============================================
% CONFIGURATION DES LISTINGS (CODE)
% ============================================
\lstset{
    backgroundcolor=\color{gray!10},
    frame=single,
    framesep=5pt,
    rulecolor=\color{gray!50},
    basicstyle=\ttfamily\footnotesize,
    keywordstyle=\color{blue}\bfseries,
    commentstyle=\color{green!60!black},
    stringstyle=\color{red},
    numberstyle=\tiny\color{gray},
    numbers=left,
    numbersep=5pt,
    breaklines=true,
    breakatwhitespace=true,
    tabsize=2,
    showstringspaces=false,
    captionpos=b
}

% Définition pour Python
\lstdefinestyle{python}{
    language=Python,
    morekeywords={def,class,if,else,elif,for,while,return,import,from,as,try,except,with,None,True,False}
}

% Définition pour JSON
\lstdefinestyle{json}{
    language=json
}

% ============================================
% CONFIGURATION DES TABLEAUX
% ============================================
\renewcommand{\arraystretch}{1.2}

% ============================================
% CONFIGURATION DES LIENS
% ============================================
\hypersetup{
    colorlinks=true,
    linkcolor=blue,
    filecolor=blue,
    urlcolor=blue,
    citecolor=blue,
    pdftitle={IoZnIzEr - Rapport de Projet},
    pdfauthor={[Votre Nom]},
    pdfsubject={Analyse de Malware avec LLM}
}

% ============================================
% DÉBUT DU DOCUMENT
% ============================================
\begin{document}

% ============================================
% PAGE DE TITRE
% ============================================
\begin{titlepage}
    \centering
    
    % Nom de l'institution
    {\Large\bfseries Ecole Nationale des Sciences Appliquees - Fes\par}
    \vspace{0.5cm}
    {\large GSCSI\par}
    \vspace{2cm}
    
    % Titre principal
    {\Huge\bfseries IoZnIzEr\par}
    \vspace{0.5cm}
    {\LARGE\bfseries Analyseur de Malware avec LLM\par}
    \vspace{1cm}
    
    % Type de document
    {\Large Rapport de Projet\par}
    \vspace{2cm}
    
    % Informations académiques
    \begin{flushleft}
        \large
        \vspace{0.5cm}
        \textbf{Année académique :} 2024-2025\par
    \end{flushleft}
    
    
    % Auteur et encadrant
    \begin{flushleft}
        \large
        \textbf{Étudiant :} Nizar YARTAOUI\par
        \vspace{0.5cm}
        \textbf{Encadrant :} M. Safae SOSSI ALAOUI\par
    \end{flushleft}
    
    \vspace{2cm}
    
    % Date
    {\large Fes, le 12 décembre 2025}
    
    \vfill
    
    % Note
    
\end{titlepage}

% ============================================
% PAGE DE RÉSUMÉ
% ============================================
\newpage
\section*{Résumé}
\addcontentsline{toc}{section}{Résumé}

Ce rapport présente \textbf{IoZnIzEr}, un système automatisé d'analyse de malware qui combine l'analyse statique traditionnelle des binaires ELF avec les capacités d'analyse intelligente des modèles de langage (LLM). Face à l'augmentation constante des cybermenaces et à la complexité croissante des malwares, ce projet vise à automatiser le processus d'analyse en générant des rapports structurés et actionnables.

Le système suit une architecture modulaire en trois phases : (1) extraction statique utilisant des outils Linux standards (readelf, objdump, strings), (2) analyse intelligente via un LLM via l'API OpenRouter avec un système d'outils itératifs permettant une investigation approfondie, et (3) génération de rapports structurés en JSON et Markdown incluant la classification, les indicateurs de compromission (IOCs), les techniques MITRE ATT\&CK, et des recommandations de mitigation.

Les résultats démontrent que le système peut analyser efficacement différents types de malwares (backdoors, downloaders, DDoS bots) en moins de 3 minutes, générant des rapports lisibles et structurés compatibles avec les formats professionnels. Les principales forces incluent la rapidité d'analyse, la génération de rapports explicables, et l'évolutivité grâce au choix flexible du modèle LLM. Les limitations identifiées concernent la dépendance à la qualité du prompt, les risques d'hallucinations du LLM, et l'analyse limitée aux binaires ELF en mode statique uniquement.

\textbf{Mots-clés :} Analyse de malware, Intelligence Artificielle, LLM, Cybersécurité, Analyse statique, OpenRouter


% ============================================
% TABLE DES MATIÈRES
% ============================================
\newpage
\tableofcontents
\newpage
\newpage

% ============================================
% CORPS DU DOCUMENT
% ============================================

\section{Introduction}

\subsection{Présentation du Projet}

\textbf{IoZnIzEr} (prononcé "Ionizer") est un outil d'analyse de malware automatisé qui combine l'analyse statique traditionnelle des binaires ELF (Executable and Linkable Format) avec les capacités d'analyse intelligente des modèles de langage (LLM - Large Language Models). Le projet vise à automatiser et améliorer le processus d'analyse de malware en générant des rapports structurés et actionnables sur le comportement malveillant des fichiers suspects.

\subsection{Contexte et Motivation}

Le paysage des cybermenaces évolue rapidement, avec une augmentation constante du nombre et de la sophistication des malwares. Les analystes en sécurité sont confrontés à plusieurs défis :

\begin{itemize}
    \item \textbf{Volume croissant} : Des milliers de nouveaux échantillons de malware sont découverts quotidiennement
    \item \textbf{Complexité accrue} : Les techniques d'évasion et d'obfuscation rendent l'analyse manuelle longue et fastidieuse
    \item \textbf{Besoins en expertise} : L'analyse approfondie requiert des connaissances spécialisées en reverse engineering, analyse de binaires et intelligence sur les menaces
    \item \textbf{Temps de réponse} : La rapidité d'analyse est cruciale pour la détection et la réponse aux incidents
\end{itemize}

Face à ces défis, l'automatisation de l'analyse de malware devient essentielle. Les LLM offrent une opportunité unique de combiner la compréhension contextuelle du langage naturel avec l'analyse technique, permettant de générer des rapports compréhensibles et structurés.

\subsection{Objectif Principal}

L'objectif principal de ce projet est de créer un système automatisé qui :

\begin{enumerate}
    \item \textbf{Extrait automatiquement} les caractéristiques statiques des binaires ELF (métadonnées, chaînes de caractères, symboles, désassemblage)
    \item \textbf{Analyse intelligemment} ces données à l'aide d'un LLM pour identifier les comportements malveillants
    \item \textbf{Génère des rapports structurés} en format JSON et Markdown, incluant :
    \begin{itemize}
        \item Classification du malware
        \item Indicateurs de compromission (IOCs)
        \item Techniques MITRE ATT\&CK identifiées
        \item Recommandations de détection et de mitigation
        \item Score de risque quantifié
    \end{itemize}
\end{enumerate}

\subsection{Portée du Projet}

Le projet se concentre sur l'analyse statique des binaires ELF (Linux/Unix), en utilisant une approche hybride combinant :
\begin{itemize}
    \item Outils d'analyse statique traditionnels (readelf, objdump, strings)
    \item Intelligence artificielle via LLM pour l'interprétation et la synthèse
    \item Système d'outils itératifs permettant au LLM de requêter des informations spécifiques
\end{itemize}
\vspace{2cm}
\section{Architecture et Technologies}

\subsection{Stack Technique}

Le projet est entièrement développé en \textbf{Python 3.13}, choisi pour sa richesse en bibliothèques, sa simplicité d'utilisation et sa compatibilité avec les outils d'analyse de binaires Linux.

\subsubsection{Bibliothèques Principales}

\textbf{OpenAI SDK (openai>=1.0.0)}
\begin{itemize}
    \item Utilisé comme client API pour communiquer avec OpenRouter
    \item Compatible avec l'interface OpenAI standard, permettant une intégration transparente
    \item Gestion native des appels de fonctions (function calling) pour le système d'outils
\end{itemize}

\textbf{python-dotenv (>=1.0.0)}
\begin{itemize}
    \item Gestion des variables d'environnement et des clés API
    \item Permet la configuration sécurisée sans hardcoder les credentials
\end{itemize}

\textbf{Bibliothèques standard Python}
\begin{itemize}
    \item \texttt{subprocess} : Exécution des outils système (readelf, objdump, strings)
    \item \texttt{pathlib} : Gestion moderne des chemins de fichiers
    \item \texttt{json} : Parsing et génération de rapports JSON structurés
    \item \texttt{re} : Extraction de patterns et parsing de texte
    \item \texttt{datetime} : Timestamping des analyses
\end{itemize}

\subsubsection{Outils Système Requis}

Le projet dépend d'outils Linux standards du package \texttt{binutils} :
\begin{itemize}
    \item \textbf{readelf} : Extraction des métadonnées ELF et des tables de symboles
    \item \textbf{objdump} : Désassemblage et analyse des en-têtes
    \item \textbf{strings} : Extraction des chaînes de caractères imprimables
\end{itemize}

Ces outils sont universellement disponibles sur les systèmes Linux et fournissent une base solide pour l'analyse statique.

\subsection{Modèle LLM Utilisé}
\begin{figure}[H]
    \centering
    \includegraphics[width=0.8\textwidth]{images/openrouter_logo.jpeg}
    \caption{Interface d'OpenRouter - Passerelle unifiée vers plusieurs modèles LLM}
    \label{fig:openrouter}
\end{figure}

Le projet utilise \textbf{OpenRouter} comme passerelle unifiée vers plusieurs modèles LLM. Le modèle par défaut configuré est :

\texttt{openai/gpt-oss-120b:free}

Ce modèle open-source de 120 milliards de paramètres offre :
\begin{itemize}
    \item Accès gratuit pour le développement et les tests
    \item Capacités de raisonnement avancées
    \item Support des appels de fonctions (function calling)
    \item Mode de raisonnement itératif (reasoning mode)
\end{itemize}

\subsubsection{Justification du Choix d'OpenRouter}

Plusieurs raisons motivent l'utilisation d'OpenRouter plutôt qu'une API directe :

\begin{enumerate}
    \item \textbf{Accès unifié à plusieurs modèles} : OpenRouter permet de basculer facilement entre différents modèles (GPT-4, Claude, Mixtral, etc.) sans modifier le code, simplement en changeant l'identifiant du modèle.
    
    \item \textbf{Rapport performance/coût} : OpenRouter offre des modèles gratuits pour le développement, tout en permettant l'utilisation de modèles premium pour la production.
    
    \item \textbf{Facilité d'API} : L'API OpenRouter est compatible avec l'interface OpenAI standard, simplifiant l'intégration et permettant l'utilisation de bibliothèques existantes.
    
    \item \textbf{Gestion de la confidentialité} : OpenRouter permet de configurer les politiques de données, important pour l'analyse de fichiers potentiellement sensibles.
    
    \item \textbf{Monitoring et analytics} : OpenRouter fournit des métriques d'utilisation et de coûts, facilitant l'optimisation.
\end{enumerate}

\subsection{Architecture Modulaire}

Le projet suit une architecture modulaire en trois phases distinctes, illustrée à la Figure~\ref{fig:architecture}.

\begin{figure}[H]
    \centering
    \begin{lstlisting}[basicstyle=\ttfamily\small, frame=none]
┌─────────────────┐
│  Fichier ELF    │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────┐
│  Phase 1: Extraction Statique   │
│  (backend/extractor.py)         │
│  - Metadonnees                  │
│  - Chaines de caracteres        │
│  - Symboles et imports          │
│  - Desassemblage                │
└────────┬────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│  Phase 2: Analyse LLM           │
│  (agent/analyze.py)             │
│  - Chargement des donnees       │
│  - Requetes LLM iteratives      │
│  - Execution d'outils           │
│  - Generation d'analyse JSON    │
└────────┬────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│  Phase 3: Generation de Rapport │
│  (agent/report_generator.py)    │
│  - Parsing JSON                 │
│  - Validation structure         │
│  - Export JSON/Markdown         │
└─────────────────────────────────┘
    \end{lstlisting}
    \caption{Architecture modulaire du système IoZnIzEr}
    \label{fig:architecture}
\end{figure}

Cette séparation permet :
\begin{itemize}
    \item \textbf{Maintenabilité} : Chaque composant a une responsabilité claire
    \item \textbf{Testabilité} : Chaque phase peut être testée indépendamment
    \item \textbf{Évolutivité} : Facile d'ajouter de nouvelles fonctionnalités à chaque phase
\end{itemize}
    \vspace{16cm}
\section{Implémentation des Prompts}

\subsection{Stratégie de Prompt Engineering}

Le système utilise une approche de \textbf{prompt engineering structuré} avec un prompt système unique et complet qui guide le LLM à travers tout le processus d'analyse. Cette approche diffère d'une stratégie multi-prompts car elle permet au LLM de maintenir le contexte complet tout au long de l'analyse itérative.

\subsection{Prompt Système Principal}

Le prompt système (défini dans \texttt{agent/analyze.py}, méthode \texttt{\_create\_system\_prompt()}) est conçu selon les principes suivants :

\subsubsection{Structure du Prompt}

\textbf{a. Définition du Rôle}

\begin{lstlisting}[frame=single]
"You are a professional malware analysis assistant with expertise in ELF binary 
analysis and threat intelligence reporting."
\end{lstlisting}

Cette déclaration établit l'identité et l'expertise attendue du LLM.

\textbf{b. Workflow Défini}

Le prompt décrit un workflow en 5 étapes :
\begin{enumerate}
    \item Réception des données d'analyse statique initiales
    \item Analyse pour identifier les patterns suspects
    \item Utilisation d'outils pour obtenir des informations détaillées si nécessaire
    \item Itération : analyse $\rightarrow$ outils $\rightarrow$ analyse $\rightarrow$ répétition
    \item Production d'une analyse finale structurée en JSON
\end{enumerate}

\textbf{c. Outils Disponibles}

Le prompt liste explicitement les 6 outils disponibles :
\begin{itemize}
    \item \texttt{read\_section} : Lecture de sections spécifiques
    \item \texttt{disassemble\_address} : Désassemblage d'adresses ou fonctions
    \item \texttt{search\_strings} : Recherche de patterns dans les chaînes
    \item \texttt{analyze\_symbol} : Analyse détaillée de symboles
    \item \texttt{get\_imports} : Liste des fonctions importées
    \item \texttt{get\_exports} : Liste des fonctions exportées
\end{itemize}

\textbf{d. Format de Sortie JSON Structuré}

Le prompt fournit un schéma JSON complet avec tous les champs requis, incluant \texttt{executive\_summary}, \texttt{technical\_analysis}, \texttt{indicators\_of\_compromise}, \texttt{threat\_intelligence}, \texttt{recommendations}, et \texttt{metadata}.

\subsubsection{Techniques de Prompt Engineering Utilisées}

\textbf{Zero-Shot Learning}

Le prompt utilise principalement une approche zero-shot, où le LLM applique ses connaissances pré-entraînées sans exemples explicites. Cette approche est efficace car les LLM modernes ont été entraînés sur de vastes corpus incluant de la documentation technique et des exemples d'analyse de malware.

\textbf{Chain-of-Thought (CoT) Implicite}

Le workflow défini encourage un raisonnement étape par étape :
\begin{itemize}
    \item "Analyze this data to identify suspicious patterns"
    \item "If you need more detailed information, use the available tools"
    \item "Continue iterating: analyze $\rightarrow$ use tools $\rightarrow$ analyze results"
\end{itemize}

\textbf{Contraintes Strictes}

Le prompt inclut des contraintes explicites pour garantir la qualité :
\begin{itemize}
    \item "CRITICAL REQUIREMENT: Your final analysis MUST be provided as a valid JSON object"
    \item "Never leave arrays empty when findings are confirmed"
    \item "No markdown formatting in JSON string fields"
\end{itemize}

\subsection{Prompt Initial Utilisateur}

Le prompt utilisateur initial (dans \texttt{analyze()}, ligne 269) sert à :

\begin{enumerate}
    \item \textbf{Fournir les données d'analyse} : Le contenu des fichiers d'extraction statique est inclus directement dans le prompt
    \item \textbf{Rappeler les exigences} : Réitère la nécessité d'un format JSON valide
    \item \textbf{Guider l'analyse} : Liste les aspects à investiguer (comportements malveillants, chaînes suspectes, communication réseau, etc.)
\end{enumerate}
\section{Explication du Code}

\subsection{Workflow Global du Projet}

Le système IoZnIzEr suit un workflow en trois phases distinctes, implémenté dans le fichier \texttt{main.py}. Chaque phase correspond à une étape précise du processus d'analyse :

\begin{enumerate}
    \item \textbf{Phase 1 - Extraction Statique} : Extraction des caractéristiques du binaire ELF via des outils système
    \item \textbf{Phase 2 - Analyse LLM} : Analyse intelligente des données extraites par un LLM avec système d'outils itératifs
    \item \textbf{Phase 3 - Génération de Rapport} : Production de rapports structurés en JSON et Markdown
\end{enumerate}

\subsection{Structure Modulaire du Projet}

Le projet est organisé en modules distincts correspondant à chaque phase du workflow :

\begin{lstlisting}[frame=single, caption=Structure du projet]
Ioznizer/
├── main.py                 # Orchestration des 3 phases
├── config.py               # Configuration centralisée
├── backend/
│   └── extractor.py        # Phase 1: Extraction statique
├── agent/
│   ├── analyze.py          # Phase 2: Analyse LLM principale
│   ├── openrouter_client.py # Client API OpenRouter
│   ├── tool_dispatcher.py  # Exécution des outils LLM
│   ├── tools_schema.py     # Définitions des outils (tools)
│   └── report_generator.py # Phase 3: Génération de rapports
└── analysis/               # Fichiers d'extraction (générés)
└── reports/                # Rapports finaux (générés)
\end{lstlisting}

\subsection{Phase 1 : Extraction Statique}

\subsubsection{Fonction de Chargement et Prétraitement du Fichier}

\textbf{Fichier :} \texttt{backend/extractor.py}  
\textbf{Classe :} \texttt{StaticExtractor}

Cette classe est responsable de la première phase du workflow. Elle valide et prépare le fichier ELF pour l'extraction :

\begin{lstlisting}[style=python, frame=single, caption=Initialisation de l'extracteur]
def __init__(self, sample_path: str, output_dir=None):
    self.sample = Path(sample_path).resolve()
    
    # Validation ELF
    if not self._is_elf_file():
        raise ValueError(f"File is not a valid ELF file")
    
    # Détection d'architecture
    self.architecture = self._detect_architecture()
\end{lstlisting}

\textbf{Fonctionnalités :}
\begin{itemize}
    \item Validation du format ELF via vérification des magic bytes (\texttt{\textbackslash x7fELF})
    \item Détection automatique de l'architecture (ARM, x86-64, MIPS, etc.) via \texttt{readelf -h}
    \item Vérification de la disponibilité des outils requis (readelf, objdump, strings)
    \item Création du répertoire de sortie pour les fichiers d'analyse
\end{itemize}

\subsubsection{Fonction d'Extraction des Caractéristiques Statiques}

Les méthodes d'extraction génèrent les fichiers texte qui seront ensuite analysés par le LLM :

\textbf{a. Extraction de Métadonnées}

\begin{lstlisting}[style=python, frame=single, caption=Extraction de métadonnées ELF]
def extract_metadata(self):
    output = self._run(f"readelf -a {self.sample}")
    (self.out_dir / "metadata.txt").write_text(output)
    return output
\end{lstlisting}

Utilise \texttt{readelf -a} pour obtenir toutes les informations ELF, incluant : en-têtes, sections, segments, tables de symboles, informations de débogage.

\textbf{b. Extraction de Chaînes}

\begin{lstlisting}[style=python, frame=single, caption=Extraction de chaînes de caractères]
def extract_strings(self):
    output = self._run(f"strings -a {self.sample}")
    (self.out_dir / "strings.txt").write_text(output)
    return output
\end{lstlisting}

Extrait toutes les chaînes imprimables (minimum 4 caractères par défaut), révélant souvent : URLs, chemins de fichiers, commandes, messages d'erreur.

\subsection{Phase 2 : Analyse LLM avec Système d'Outils}

\subsubsection{Workflow de l'Analyse LLM}

La phase 2 est orchestrée par la classe \texttt{MalwareAnalyzer} dans \texttt{agent/analyze.py}. Le workflow implémente une boucle itérative où le LLM peut requêter des outils pour approfondir son analyse :

\begin{enumerate}
    \item \textbf{Initialisation} : Création du prompt système et du prompt utilisateur initial
    \item \textbf{Boucle itérative} : Envoi de requêtes au LLM avec historique de conversation
    \item \textbf{Gestion des outils} : Exécution des outils demandés par le LLM
    \item \textbf{Itération} : Retour des résultats d'outils au LLM pour analyse continue
    \item \textbf{Terminaison} : Arrêt lorsque le LLM produit l'analyse finale en JSON
\end{enumerate}

\subsubsection{Prompt Système Envoyé au LLM}

Le prompt système est généré par la méthode \texttt{\_create\_system\_prompt()} et définit le rôle, le workflow et les contraintes pour le LLM :

\begin{lstlisting}[frame=single, caption=Extrait du prompt système]
You are a professional malware analysis assistant with expertise 
in ELF binary analysis and threat intelligence reporting.

CRITICAL REQUIREMENT: Your final analysis MUST be provided as a 
valid JSON object matching the exact structure specified below.

WORKFLOW:
1. You will receive initial static analysis data 
   (metadata, strings, symbols, disassembly, etc.)
2. Analyze this data to identify suspicious patterns
3. If you need more detailed information, use the available tools 
   to query specific sections
4. Continue iterating: analyze → use tools if needed → 
   analyze results → repeat until complete
5. When you have a comprehensive understanding, provide your 
   final analysis as structured JSON

AVAILABLE TOOLS (use when you need more information):
- read_section: Read specific sections from analysis files
- disassemble_address: Get disassembly for specific addresses
- search_strings: Search for suspicious strings or patterns
- analyze_symbol: Get detailed information about symbols
- get_imports: List imported functions and libraries
- get_exports: List exported functions
\end{lstlisting}

Ce prompt est envoyé au LLM dans le message système lors de l'initialisation de la conversation (ligne 262-265 de \texttt{analyze.py}) :

\begin{lstlisting}[style=python, frame=single, caption=Initialisation de la conversation]
system_message = {
    "role": "system",
    "content": self._create_system_prompt()
}
\end{lstlisting}

\subsubsection{Prompt Utilisateur Initial}

Le prompt utilisateur initial contient les données d'extraction statique et guide le LLM sur les aspects à investiguer :

\begin{lstlisting}[frame=single, caption=Extrait du prompt utilisateur initial]
Analyze this malware sample. I've extracted the following 
static analysis data from the ELF binary:

[contenu des fichiers metadata.txt, strings.txt, symbols.txt, 
disasm.txt, decomp.txt - tronqués à 10000 caractères chacun]

CRITICAL: Your final output MUST be a valid JSON object matching 
the structure specified in the system prompt.

Analyze this data and identify:
1. Malicious behaviors and indicators
2. Suspicious strings, API calls, and functions
3. Network communication patterns
4. File system operations
5. Process manipulation
6. Anti-analysis techniques

If you need more detailed information about specific sections, 
addresses, or strings, use the available tools to query deeper.
\end{lstlisting}

Ce prompt est construit dans la méthode \texttt{analyze()} (lignes 267-293) et inclut le contenu des fichiers d'extraction via \texttt{self.analysis\_content}.

\subsubsection{Système d'Outils (Tools)}

\paragraph{Définition des Outils}

Les outils disponibles pour le LLM sont définis dans \texttt{agent/tools\_schema.py} au format JSON Schema. Chaque outil est décrit avec son nom, sa description et ses paramètres :

\begin{lstlisting}[style=json, frame=single, caption=Exemple de définition d'outil - search_strings]
{
  "type": "function",
  "function": {
    "name": "search_strings",
    "description": "Search for specific strings or patterns in 
                    the extracted strings. Useful for finding 
                    suspicious strings, URLs, file paths, or 
                    other indicators.",
    "parameters": {
      "type": "object",
      "properties": {
        "pattern": {
          "type": "string",
          "description": "The string or pattern to search for 
                         (case-insensitive substring match)"
        },
        "max_results": {
          "type": "integer",
          "description": "Maximum number of results to return 
                         (default: 20)",
          "default": 20
        }
      },
      "required": ["pattern"]
    }
  }
}
\end{lstlisting}

Les six outils disponibles sont :
\begin{itemize}
    \item \texttt{read\_section} : Lit des sections spécifiques des fichiers d'analyse (metadata, strings, symbols, disasm, decomp)
    \item \texttt{disassemble\_address} : Obtient le désassemblage pour des adresses ou fonctions spécifiques
    \item \texttt{search\_strings} : Recherche des patterns dans les chaînes extraites
    \item \texttt{analyze\_symbol} : Obtient des informations détaillées sur un symbole
    \item \texttt{get\_imports} : Liste les fonctions et bibliothèques importées
    \item \texttt{get\_exports} : Liste les fonctions exportées
\end{itemize}

\paragraph{Envoi des Outils au LLM}

Les outils sont envoyés au LLM lors de chaque appel API via le paramètre \texttt{tools} :

\begin{lstlisting}[style=python, frame=single, caption=Appel API avec outils]
response = self.client.chat_completion(
    messages=self.conversation_history,
    tools=self.tools_schema,  # Schéma JSON des outils
    tool_choice="auto",        # LLM décide quand utiliser les outils
    temperature=0.7,
    max_tokens=4000
)
\end{lstlisting}

Le paramètre \texttt{tool\_choice="auto"} permet au LLM de décider automatiquement quand utiliser les outils en fonction de son analyse.

\paragraph{Exécution des Outils}

Lorsque le LLM demande l'utilisation d'un outil, la réponse contient un champ \texttt{tool\_calls} avec les appels de fonctions. Le code exécute ces outils via le \texttt{ToolDispatcher} :

\begin{lstlisting}[style=python, frame=single, caption=Exécution des outils demandés par le LLM]
tool_calls = message.get("tool_calls", [])

if tool_calls:
    tool_messages = []
    
    for tool_call in tool_calls:
        tool_id = tool_call["id"]
        tool_name = tool_call["function"]["name"]
        tool_args = json.loads(tool_call["function"]["arguments"])
        
        # Exécution de l'outil
        tool_result = self.dispatcher.execute_tool(tool_name, tool_args)
        
        # Formatage du résultat pour le LLM
        tool_response = f"Tool {tool_name} executed successfully:\n{result_content}"
        
        # Ajout à l'historique de conversation
        tool_messages.append({
            "role": "tool",
            "tool_call_id": tool_id,
            "content": tool_response
        })
    
    # Ajout des résultats d'outils à l'historique
    self.conversation_history.extend(tool_messages)
    # Le LLM recevra ces résultats et continuera son analyse
\end{lstlisting}

\paragraph{Boucle Itérative Complète}

La boucle itérative dans \texttt{analyze()} (lignes 300-496) implémente le workflow complet :

\begin{lstlisting}[style=python, frame=single, caption=Boucle itérative d'analyse]
while iteration < max_iterations:
    iteration += 1
    
    # 1. Envoi de la requête au LLM avec historique complet
    response = self.client.chat_completion(
        messages=self.conversation_history,
        tools=self.tools_schema,
        tool_choice="auto"
    )
    
    message = response["choices"][0]["message"]
    tool_calls = message.get("tool_calls", [])
    
    if tool_calls:
        # 2. Le LLM demande des outils - exécution
        for tool_call in tool_calls:
            tool_result = self.dispatcher.execute_tool(...)
            # Ajout des résultats à l'historique
        
        # 3. Continuation de la boucle pour que le LLM 
        #    analyse les résultats d'outils
        continue
    else:
        # 4. Pas d'outils = analyse finale probable
        final_analysis = message.get("content")
        break
\end{lstlisting}

Cette approche permet au LLM de mener une investigation approfondie en requêtant des informations spécifiques au fur et à mesure de son analyse, plutôt que de recevoir toutes les données d'un coup.

\subsubsection{Fonction d'Appel à l'API OpenRouter}

\textbf{Fichier :} \texttt{agent/openrouter\_client.py}  
\textbf{Classe :} \texttt{OpenRouterClient}

La méthode \texttt{chat\_completion()} encapsule l'appel à l'API OpenRouter :

\begin{lstlisting}[style=python, frame=single, caption=Méthode principale d'appel API]
def chat_completion(
    self,
    messages: List[Dict[str, str]],
    tools: Optional[List[Dict]] = None,
    tool_choice: Optional[str] = None,
    temperature: float = 0.7,
    max_tokens: Optional[int] = None,
    max_retries: int = 3
) -> Dict[str, Any]:
\end{lstlisting}

\textbf{Paramètres Clés :}
\begin{itemize}
    \item \texttt{messages} : Historique de conversation complet (système, utilisateur, assistant, outils)
    \item \texttt{tools} : Schéma JSON des outils disponibles (function calling)
    \item \texttt{tool\_choice} : Mode de sélection ("auto" = LLM décide quand utiliser les outils)
    \item \texttt{temperature} : 0.7 (équilibre créativité/cohérence)
    \item \texttt{max\_tokens} : 4000 (suffisant pour rapports complets)
    \item \texttt{max\_retries} : 3 tentatives avec backoff exponentiel en cas d'erreur
\end{itemize}

\subsection{Phase 3 : Génération de Rapport}

\subsubsection{Fonction de Parsing et Formatage des Réponses LLM}

\textbf{Fichier :} \texttt{agent/report\_generator.py}  
\textbf{Méthode :} \texttt{\_extract\_json\_from\_text()}

Le parsing des réponses LLM est complexe car le LLM peut retourner du JSON dans différents formats (code blocks, JSON brut, etc.). La méthode \texttt{\_extract\_balanced\_json()} gère les chaînes JSON contenant des braces, les caractères d'échappement, et trouve le premier objet JSON complet et valide.

\subsubsection{Fonction de Génération de Rapport Final}

Les méthodes \texttt{\_generate\_json\_report()} et \texttt{\_generate\_markdown\_report()} produisent les rapports finaux à partir de l'analyse JSON structurée extraite de la réponse du LLM.

\section{Intégration de l'API OpenRouter}

\subsection{Configuration de l'API}

\textbf{Fichier :} \texttt{config.py}

\begin{lstlisting}[style=python, frame=single, caption=Configuration OpenRouter]
class Config:
    DEFAULT_API_KEY = "sk-or-v1-..."
    OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY") or DEFAULT_API_KEY
    OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "openai/gpt-oss-120b:free")
\end{lstlisting}

\textbf{Priorité de Configuration :}
\begin{enumerate}
    \item Variable d'environnement \texttt{OPENROUTER\_API\_KEY} (recommandé pour la production)
    \item Valeur par défaut dans \texttt{config.py} (pour le développement)
\end{enumerate}

\subsection{Endpoint et Paramètres de Requête}

\textbf{Base URL :} \texttt{https://openrouter.ai/api/v1}

\textbf{Paramètres de Requête Standard :}

\begin{lstlisting}[style=json, frame=single, caption=Paramètres de requête OpenRouter]
{
  "model": "openai/gpt-oss-120b:free",
  "messages": [
    {"role": "system", "content": system_prompt},
    {"role": "user", "content": user_message}
  ],
  "temperature": 0.7,
  "max_tokens": 4000,
  "tools": tools_schema,
  "tool_choice": "auto"
}
\end{lstlisting}

\subsection{Gestion de la Confidentialité}

\textbf{Principe Fondamental : Aucun fichier binaire n'est envoyé à l'API}

Le système garantit la confidentialité de plusieurs manières :

\begin{enumerate}
    \item \textbf{Extraction Locale} : Tous les outils d'extraction (readelf, objdump, strings) s'exécutent localement
    \item \textbf{Envoi de Données Textuelles Uniquement} : Seules les caractéristiques extraites et textualisées sont transmises
    \item \textbf{Pas de Fichiers Binaires} : Le fichier \texttt{.elf} original n'est jamais lu pour être envoyé
    \item \textbf{Truncation Intelligente} : Les fichiers volumineux sont tronqués à 10 000 caractères par défaut
\end{enumerate}

\subsection{Gestion des Coûts et Consommation}

\textbf{Modèle Gratuit :}
\begin{itemize}
    \item \texttt{openai/gpt-oss-120b:free} : Aucun coût pour le développement
    \item Limites de taux possibles (gérées par retry logic)
\end{itemize}

\textbf{Estimation de Coûts (pour modèles payants) :}
\begin{itemize}
    \item Prompt initial : $\sim$2000-5000 tokens (données d'extraction)
    \item Chaque itération : $\sim$500-2000 tokens (réponses + résultats d'outils)
    \item Total par analyse : $\sim$5000-15000 tokens
    \item Avec GPT-4 : $\sim$\$0.03-0.10 par analyse
    \item Avec modèles moins chers : $\sim$\$0.001-0.01 par analyse
\end{itemize}

\section{Résultats et Discussion}

\subsection{Capacités de l'Outil}

Le système IoZnIzEr a été testé sur différents types de malwares ELF :

\subsubsection{Types de Malwares Testés}

\textbf{a. Backdoors}
\begin{itemize}
    \item \textbf{Capacités identifiées} : Communication C2, écoute de ports, exécution de commandes distantes
    \item \textbf{IOCs extraits} : Adresses IP, domaines, ports d'écoute
    \item \textbf{Techniques MITRE} : T1071 (Application Layer Protocol), T1059 (Command and Scripting Interpreter)
\end{itemize}

\textbf{b. Downloaders}
\begin{itemize}
    \item \textbf{Capacités identifiées} : Téléchargement de fichiers depuis URLs, exécution de payloads
    \item \textbf{IOCs extraits} : URLs de téléchargement, chemins de fichiers temporaires
    \item \textbf{Techniques MITRE} : T1105 (Ingress Tool Transfer)
\end{itemize}

\textbf{c. DDoS Bots}
\begin{itemize}
    \item \textbf{Capacités identifiées} : Communication avec serveurs de commande, génération de trafic
    \item \textbf{IOCs extraits} : Adresses IP de contrôle, protocoles utilisés
    \item \textbf{Techniques MITRE} : T1498 (Denial of Service)
\end{itemize}

\subsubsection{Exemple de Rapport Généré}

\textbf{Executive Summary :}

\begin{lstlisting}[style=json, frame=single, caption=Exemple de résumé exécutif]
{
  "classification": "Backdoor",
  "key_capabilities": [
    "Remote command execution",
    "C2 communication",
    "File system access"
  ],
  "risk_level": "High",
  "risk_score": 85,
  "primary_evasion_techniques": [
    "String obfuscation",
    "Anti-debugging checks"
  ]
}
\end{lstlisting}

\subsection{Forces du Système}

\subsubsection{Analyse Rapide}
\begin{itemize}
    \item \textbf{Temps d'extraction} : 5-30 secondes (selon taille du binaire)
    \item \textbf{Temps d'analyse LLM} : 30-120 secondes (selon complexité et nombre d'itérations)
    \item \textbf{Total} : $<$ 3 minutes pour la plupart des échantillons
    \item Comparé à l'analyse manuelle : Réduction de 90\%+ du temps
\end{itemize}

\subsubsection{Rapports Lisibles et Structurés}
\begin{itemize}
    \item \textbf{Format JSON} : Facilement parsable par des outils automatisés
    \item \textbf{Format Markdown} : Lisible par les analystes humains
    \item \textbf{Structure standardisée} : Compatible avec les formats de rapports professionnels (MITRE ATT\&CK, STIX)
\end{itemize}

\subsection{Limitations et Défis}

\subsubsection{Dépendance à la Qualité du Prompt}
\begin{itemize}
    \item \textbf{Sensibilité} : Des changements mineurs dans le prompt peuvent affecter les résultats
    \item \textbf{Optimisation requise} : Le prompt système nécessite des ajustements pour différents types de malwares
    \item \textbf{Mitigation} : Documentation détaillée du prompt, tests sur échantillons variés
\end{itemize}

\subsubsection{Risques d'Hallucinations du LLM}
\begin{itemize}
    \item \textbf{Problème} : Les LLM peuvent générer des informations plausibles mais incorrectes
    \item \textbf{Exemples} : Classification erronée, IOCs inventés, techniques MITRE incorrectes
    \item \textbf{Mitigation} :
    \begin{itemize}
        \item Validation croisée avec les données d'extraction
        \item Extraction automatique d'IOCs depuis les résultats d'outils
        \item Niveaux de confiance dans le rapport
        \item Revue humaine recommandée pour analyses critiques
    \end{itemize}
\end{itemize}

\subsubsection{Analyse Dynamique Limitée}
\begin{itemize}
    \item \textbf{Limitation actuelle} : Analyse statique uniquement
    \item \textbf{Ce qui manque} : Comportement réel (appels système, modifications de fichiers, communication réseau)
    \item \textbf{Impact} : Certains malwares avec obfuscation avancée ou packers peuvent échapper à la détection
\end{itemize}

\subsection{Comparaison avec Outils Existants}

\begin{table}[H]
    \centering
    \caption{Comparaison des caractéristiques}
    \label{tab:comparaison}
    \begin{tabular}{lccc}
        \toprule
        \textbf{Caractéristique} & \textbf{IoZnIzEr} & \textbf{Outils Traditionnels} & \textbf{Analyseurs ML} \\
        \midrule
        Rapidité & **** & ** & *** \\
        Lisibilité des rapports & ***** & *** & ** \\
        Explicabilité & ***** & **** & ** \\
        Coût & *** & ***** & **** \\
        Précision & **** & ***** & **** \\
        Évolutivité & ***** & ** & *** \\
        \bottomrule
    \end{tabular}
\end{table}

\textbf{Avantages uniques d'IoZnIzEr :}
\begin{itemize}
    \item Génération de rapports en langage naturel structuré
    \item Mapping automatique vers MITRE ATT\&CK
    \item Raisonnement explicite (via outils itératifs)
    \item Pas besoin d'entraînement de modèle spécifique
\end{itemize}
    \vspace{8cm}
\section{Conclusion et Perspectives}

\subsection{Valeur Académique et Pratique}

\subsubsection{Contribution Académique}

Ce projet démontre l'application pratique des LLM à un domaine technique spécialisé (analyse de malware). Les contributions incluent :

\begin{enumerate}
    \item \textbf{Architecture hybride} : Combinaison efficace d'outils traditionnels et d'IA générative
    \item \textbf{Système d'outils itératifs} : Approche permettant au LLM de mener une investigation approfondie
    \item \textbf{Prompt engineering spécialisé} : Démonstration de techniques pour guider les LLM vers des sorties structurées et fiables
    \item \textbf{Évaluation pratique} : Tests sur échantillons réels et analyse des forces/limitations
\end{enumerate}

\subsubsection{Valeur Pratique}

Pour les professionnels de la cybersécurité :
\begin{itemize}
    \item \textbf{Automatisation} : Réduction significative du temps d'analyse
    \item \textbf{Standardisation} : Rapports structurés compatibles avec les outils SIEM/SOAR
    \item \textbf{Accessibilité} : Permet aux analystes moins expérimentés de produire des analyses de qualité
    \item \textbf{Documentation} : Génération automatique de documentation d'incidents
\end{itemize}

\subsection{Améliorations Futures}

\subsubsection{Intégration de Sandbox pour Analyse Dynamique}

\textbf{Objectif} : Compléter l'analyse statique par l'observation du comportement réel

\textbf{Implémentation proposée :}
\begin{itemize}
    \item Intégration avec Cuckoo Sandbox ou CAPE
    \item Exécution contrôlée du malware dans environnement isolé
    \item Capture des appels système, modifications de fichiers, trafic réseau
    \item Enrichissement du prompt LLM avec données comportementales
\end{itemize}

\subsubsection{Fine-Tuning d'un Modèle Spécialisé}

\textbf{Objectif} : Améliorer la précision et réduire les hallucinations

\textbf{Approche :}
\begin{itemize}
    \item Collecte d'un dataset d'analyses de malware annotées
    \item Fine-tuning d'un modèle open-source (Llama, Mistral) sur ce dataset
    \item Spécialisation sur le domaine de l'analyse de malware
\end{itemize}

\subsubsection{Interface Web}

\textbf{Objectif} : Rendre l'outil accessible via une interface utilisateur moderne

\textbf{Stack technique suggéré :}
\begin{itemize}
    \item Backend : FastAPI (Python)
    \item Frontend : React ou Vue.js
    \item Base de données : PostgreSQL pour historique
\end{itemize}

\subsubsection{Support de Formats Additionnels}

\textbf{Formats à ajouter :}
\begin{itemize}
    \item \textbf{PE (Windows)} : Adaptation de l'extracteur pour utiliser \texttt{pefile} ou outils Windows
    \item \textbf{Mach-O (macOS)} : Support via \texttt{otool} et \texttt{macholib}
    \item \textbf{Scripts} : Analyse de scripts Python, PowerShell, shell
    \item \textbf{Documents} : Extraction et analyse de macros (Office, PDF)
\end{itemize}

\subsection{Impact Potentiel}

\textbf{Court terme (6-12 mois) :}
\begin{itemize}
    \item Outil utilisable par des équipes SOC pour triage initial
    \item Réduction de 50\%+ du temps d'analyse par échantillon
    \item Intégration dans pipelines de sécurité existants
\end{itemize}

\textbf{Moyen terme (1-2 ans) :}
\begin{itemize}
    \item Adoption par des organisations de taille moyenne
    \item Contribution à la recherche académique (publications)
    \item Amélioration continue basée sur retours utilisateurs
\end{itemize}

\textbf{Long terme (2+ ans) :}
\begin{itemize}
    \item Standard de l'industrie pour analyse automatisée
    \item Intégration dans solutions commerciales
    \item Base pour systèmes de détection en temps réel
\end{itemize}
    \vspace{10cm}
\section{Références}

\subsection{Documentation Technique}

\textbf{OpenRouter}
\begin{itemize}
    \item OpenRouter Documentation. (2024). \textit{API Reference}. \url{https://openrouter.ai/docs}
    \item OpenRouter. (2024). \textit{Models}. \url{https://openrouter.ai/models}
\end{itemize}

\textbf{OpenAI SDK}
\begin{itemize}
    \item OpenAI. (2024). \textit{Python API Reference}. \url{https://platform.openai.com/docs/api-reference}
    \item OpenAI. (2024). \textit{Function Calling}. \url{https://platform.openai.com/docs/guides/function-calling}
\end{itemize}

\textbf{Outils d'Analyse Binaire}
\begin{itemize}
    \item GNU Binutils. (2024). \textit{readelf, objdump, strings Documentation}. \url{https://sourceware.org/binutils/docs/binutils/}
    \item ELF Format Specification. (2024). \textit{Executable and Linkable Format (ELF)}. \url{https://refspecs.linuxfoundation.org/elf/elf.pdf}
\end{itemize}

\subsection{Articles Académiques}

\textbf{Analyse de Malware avec IA}
\begin{itemize}
    \item Raff, E., et al. (2018). "Malware Detection by Eating a Whole EXE". \textit{Workshop on Artificial Intelligence for Cybersecurity (AICS)}.
    \item Anderson, H. S., \& Roth, P. (2018). "EMBER: An Open Dataset for Training Static PE Malware Machine Learning Models". \textit{arXiv preprint arXiv:1804.04637}.
\end{itemize}

\textbf{LLM pour Cybersécurité}
\begin{itemize}
    \item Li, B., et al. (2023). "A Survey on Large Language Models for Cybersecurity". \textit{arXiv preprint arXiv:2312.05986}.
    \item Mijwil, M. M., et al. (2024). "ChatGPT and the Future of Cybersecurity: Benefits and Challenges". \textit{International Journal of Computer Science and Security}.
\end{itemize}

\textbf{Prompt Engineering}
\begin{itemize}
    \item Wei, J., et al. (2022). "Chain-of-Thought Prompting Elicits Reasoning in Large Language Models". \textit{Advances in Neural Information Processing Systems}.
    \item Brown, T., et al. (2020). "Language Models are Few-Shot Learners". \textit{Advances in Neural Information Processing Systems}.
\end{itemize}

\subsection{Frameworks et Standards}

\textbf{MITRE ATT\&CK}
\begin{itemize}
    \item MITRE Corporation. (2024). \textit{MITRE ATT\&CK Framework}. \url{https://attack.mitre.org/}
\end{itemize}

\textbf{STIX/TAXII}
\begin{itemize}
    \item OASIS. (2024). \textit{Structured Threat Information Expression (STIX)}. \url{https://oasis-open.github.io/cti-documentation/}
\end{itemize}

\textbf{YARA}
\begin{itemize}
    \item YARA Rules. (2024). \textit{The Pattern Matching Swiss Knife for Malware Researchers}. \url{https://yara.readthedocs.io/}
\end{itemize}

\subsection{Ressources Complémentaires}

\textbf{Datasets de Malware}
\begin{itemize}
    \item VirusShare. (2024). \textit{VirusShare.com - Malware Research Database}. \url{https://virusshare.com/}
    \item MalwareBazaar. (2024). \textit{MalwareBazaar by abuse.ch}. \url{https://bazaar.abuse.ch/}
\end{itemize}

\textbf{Outils de Sandbox}
\begin{itemize}
    \item Cuckoo Sandbox. (2024). \textit{Automated Malware Analysis}. \url{https://cuckoosandbox.org/}
    \item CAPE Sandbox. (2024). \textit{Malware Configuration And Payload Extraction}. \url{https://github.com/kevoreilly/CAPEv2}
\end{itemize}

% ============================================
% ANNEXES
% ============================================
\newpage
\appendix
\section{Structure Complète du Rapport JSON}

Le rapport généré suit une structure complète incluant les sections suivantes :

\begin{lstlisting}[style=json, frame=single, caption=Structure du rapport JSON]
{
  "executive_summary": {
    "classification": "string",
    "key_capabilities": ["array"],
    "risk_level": "string",
    "risk_score": 0-100,
    "primary_evasion_techniques": ["array"]
  },
  "technical_analysis": {
    "static_properties": {},
    "behavioral_indicators": [],
    "network_activity": [],
    "file_operations": []
  },
  "indicators_of_compromise": {
    "ip_addresses": [],
    "domains": [],
    "file_hashes": {},
    "mutex_names": [],
    "registry_keys": []
  },
  "threat_intelligence": {
    "mitre_attack_techniques": [],
    "threat_actor_attribution": {},
    "campaign_indicators": []
  },
  "recommendations": {
    "detection_rules": [],
    "mitigation_steps": [],
    "hunting_queries": []
  },
  "metadata": {
    "analysis_date": "ISO8601",
    "analyzer_version": "string",
    "confidence_score": 0-100
  }
}
\end{lstlisting}

Pour le schéma détaillé, voir \texttt{agent/analyze.py}, lignes 112-198.

\section{Exemple de Prompt Système Complet}

Le prompt système complet guide le LLM à travers toutes les étapes d'analyse. Voici un extrait :

\begin{lstlisting}[frame=single, caption=Extrait du prompt système]
You are a professional malware analysis assistant with expertise 
in ELF binary analysis and threat intelligence reporting.

Your workflow:
1. Receive initial static analysis data
2. Analyze to identify suspicious patterns
3. Use available tools for detailed information
4. Iterate: analyze -> tools -> analyze -> repeat
5. Produce final structured JSON analysis

Available tools:
- read_section: Read specific sections
- disassemble_address: Disassemble addresses/functions
- search_strings: Search patterns in strings
- analyze_symbol: Detailed symbol analysis
- get_imports: List imported functions
- get_exports: List exported functions

CRITICAL: Your final analysis MUST be valid JSON.
\end{lstlisting}

Le prompt complet est disponible dans \texttt{agent/analyze.py}, méthode \texttt{\_create\_system\_prompt()} (lignes 82-219).

\section{Schéma des Outils}

Les outils disponibles pour le LLM sont définis avec le format JSON Schema :

\begin{lstlisting}[style=json, frame=single, caption=Exemple de définition d'outil]
{
  "type": "function",
  "function": {
    "name": "search_strings",
    "description": "Search for specific patterns in extracted strings",
    "parameters": {
      "type": "object",
      "properties": {
        "pattern": {
          "type": "string",
          "description": "Regex pattern to search"
        },
        "case_sensitive": {
          "type": "boolean",
          "description": "Case sensitive search",
          "default": false
        }
      },
      "required": ["pattern"]
    }
  }
}
\end{lstlisting}

Les définitions complètes des outils sont dans \texttt{agent/tools\_schema.py} (lignes 6-135).

\section{Exemple de Commandes d'Exécution}

\subsection{Installation des Dépendances}

\begin{lstlisting}[language=bash, frame=single, caption=Installation]
# Installer les dépendances Python
pip install -r requirements.txt

# Vérifier la disponibilité des outils système
which readelf objdump strings

# Sur Debian/Ubuntu
sudo apt-get install binutils
\end{lstlisting}

\subsection{Exécution de l'Analyse}

\begin{lstlisting}[language=bash, frame=single, caption=Commandes d'exécution]
# Analyse d'un échantillon
python main.py /path/to/malware.elf

# Avec un modèle spécifique
OPENROUTER_MODEL="anthropic/claude-3-5-sonnet" python main.py sample.elf

# Avec clé API personnalisée
OPENROUTER_API_KEY="sk-or-v1-xxx" python main.py sample.elf
\end{lstlisting}

\subsection{Structure des Fichiers Générés}

\begin{lstlisting}[frame=single, caption=Arborescence des résultats]
analysis/
└── sample_elf_20241215_143022/
    ├── metadata.txt
    ├── strings.txt
    ├── disassembly.txt
    └── symbols.txt

reports/
└── sample_elf_20241215_143022/
    ├── analysis.json
    └── report.md
\end{lstlisting}

% ============================================
% FIN DU DOCUMENT
% ============================================
\end{document}
