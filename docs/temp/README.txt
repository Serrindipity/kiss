PENETRATION TEST REPORT TEMPLATE

Start with report.tex. It is self-contained and requires no logos, custom
fonts, scripts, or external images. All assessment content is a placeholder;
the sample High rating is not an actual finding.

Build
-----
Overleaf: create a blank project, upload report.tex, set it as the main
document, and use the pdfLaTeX compiler.

Locally, with a LaTeX distribution and the required packages installed:
  latexmk -pdf report.tex
Or run twice to resolve the contents and cross-references:
  pdflatex -interaction=nonstopmode -halt-on-error report.tex
  pdflatex -interaction=nonstopmode -halt-on-error report.tex

Editing
-------
1. Edit the six metadata commands at the top of report.tex.
2. Replace all bracketed prompts. Write the executive summary for the client,
   connecting technical findings to business operations and priorities.
3. Fill in the finding block. To add another, copy from the first \finding
   command through the References content, but omit the surrounding
   \begingroup, \let\clearpage\relax, and \endgroup lines. Those three lines
   only keep the first finding with its section heading.
4. Give each finding a unique ID and label, such as F-02 and finding:02.
   Add its row to Findings Overview. Severity names are lowercase:
   critical, high, medium, low, informational.
5. Uncomment the screenshot block if needed and supply the matching image.
6. Remove unused appendix sections and references. Check the applicable
   engagement brief for required content.
7. Compile, inspect page breaks and links, and search the PDF for remaining
   bracketed prompts before submitting.

LaTeX basics
------------
In normal prose, write \& \% \$ \# and \_ for those special characters.
Use \url{https://example.com/path} for links. Inside lstlisting, paste text
literally without adding LaTeX escapes. A blank line starts a new paragraph.
Change letterpaper to a4paper in the first line if needed.

Validation
----------
No LaTeX compiler was available in the authoring environment. Source structure
was checked, but compilation and rendered layout still need verification.
