const boton = document.getElementById('resume')
boton.addEventListener('click', function() {
    const pdfUrl = 'https://drive.google.com/uc?export=download&id=1YQehCMNRqkMUGX62vBlUSOBI-JHQpfsv';
    const a = document.createElement('a');
    a.href = pdfUrl;
    a.download = 'resume.pdf';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    });