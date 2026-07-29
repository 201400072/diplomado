# Latexmk configuration file
# This file controls the output naming for LaTeX compilation.
# Based on the official Latexmk recipe format for BasicTeX in Visual Studio Code.

# 1. Define default files to process
@default_files = ('monografia_soc_diplomado.tex');

# 2. Define the output commands for DVI, PostScript and PDF
#    Using lualatex with the -jobname flag sets the BASE NAME of the output files.
#    Example: -jobname="CRISTAL FLORES" -> produces "CRISTAL FLORES.pdf", "CRISTAL FLORES.aux", etc.
$DVI    = 'lualatex %O -jobname="CRISTAL FLORES" %S';
$ps     = 'lualatex %O -jobname="CRISTAL FLORES" %S';
$pdf    = 'lualatex %O -jobname="CRISTAL FLORES" %S';

# 3. Auxiliary flags (optional but recommended)
$pdflatex = 'lualatex %O -interaction=nonstopmode -synctex=1 %S';
$lualatex = 'lualatex %O -interaction=nonstopmode -synctex=1 %S';
$clean_ext = 'aux bbl blg brf idx ilg ind lof lol log lot out nav snm synctex.gz toc vrb _minted* fls fdb_latexmk run.xml acn acr glg* gls* ist ocp otc';

# 4. (Optional) View command - opens the resulting PDF in the default viewer
$view = 'open -a Preview.app "CRISTAL FLORES.pdf"';

# EOF - Generated for Diplomatic Monograph "Implementación de un Sistema SOC"
