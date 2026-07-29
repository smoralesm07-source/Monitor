@echo off
setlocal
where git >nul 2>&1
if errorlevel 1 (
  echo ERROR: Git no esta instalado o no esta disponible en PATH.
  echo Descargalo desde https://git-scm.com/ y vuelve a ejecutar este archivo.
  pause
  exit /b 1
)

echo.
echo Pega la URL HTTPS del repositorio vacio.
echo Ejemplo: https://github.com/usuario/monitor-uaf.git
set /p REPO_URL=URL: 
if "%REPO_URL%"=="" (
  echo No se ingreso una URL.
  pause
  exit /b 1
)

git init || goto :error
git branch -M main || goto :error
git add . || goto :error
git commit -m "Publicar monitor UAF" || goto :error
git remote remove origin >nul 2>&1
git remote add origin "%REPO_URL%" || goto :error
git push -u origin main || goto :error

echo.
echo Archivos publicados correctamente.
echo Ahora habilita Settings ^> Pages ^> Source: GitHub Actions.
pause
exit /b 0

:error
echo.
echo La publicacion fallo. Revisa el mensaje de Git mostrado arriba.
pause
exit /b 1
