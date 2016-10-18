show: vortrag.pdf
	evince -s vortrag.pdf

vortrag.pdf: vortrag.tex
	pdflatex vortrag.tex
	pdflatex vortrag.tex
	pdflatex vortrag.tex
	rm vortrag.log vortrag.nav vortrag.aux vortrag.out vortrag.snm vortrag.toc vortrag.vrb

clean:
	rm vortrag.pdf
