dotnet test /p:CollectCoverage=true /p:CoverletOutput=coverage.xml /p:CoverletOutputFormat=opencover /p:Exclude=[xunit.*]*
reportgenerator -reports:coverage.xml -targetdir:CoverageReport
pause