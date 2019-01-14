dotnet test /p:CollectCoverage=true /p:CoverletOutput=coverage.xml /p:CoverletOutputFormat=opencover
reportgenerator -reports:coverage.xml -targetdir:CoverageReport
pause