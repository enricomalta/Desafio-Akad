# Vehicle Registry API — README

## Visão geral
Este repositório contém uma API ASP.NET Core (target net9.0) para um registro de veículos com autenticação JWT, gerenciamento de usuários, refresh tokens e endpoints protegidos. O projeto já está configurado para rodar localmente no modo Development usando um banco InMemory (não necessita de LocalDB/SQL Server para testes rápidos via Swagger).

Resumo rápido:
- Framework: .NET 9 (Microsoft.NET.Sdk.Web)
- ORM: Entity Framework Core (InMemory para Development; SqlServer para Homolog/Prod)
- Autenticação: JWT (Microsoft.AspNetCore.Authentication.JwtBearer)
- Documentação: Swagger (Swashbuckle)

## Estrutura principal (arquivos importantes)
- `Program.cs` — bootstrap da aplicação, registro de serviços, middlewares e Swagger.
- `Data/ApplicationDbContext.cs` — DbContext do EF Core (DbSet: Users, Vehicles, RefreshTokens).
- `Data/DataSeeder.cs` — seeder que garante a criação do primeiro usuário admin (usado para Development).
- `Controllers/HomeController.cs` — contém endpoints públicos (status), `AuthController` (login/refresh) e `VehiclesController` (CRUD protegido).
- `Models/User.cs` — modelos: `User`, `Vehicle`, `RefreshToken`.
- `Services/IPassawordHasher.cs` — implementação de hashing de senha e `JwtService` para tokens.
- `Repository/IVehicleRepository.cs` — abstração de acesso a dados de veículos.
- `Middleware/RateLimitingMiddleware.cs` — middleware simples de limitação por IP.
- `appsettings.json` — configurações (ConnectionStrings, Jwt, Logging).
- `Desafio-Akad.csproj` — definições do projeto e pacotes NuGet.

## Como rodar localmente (desenvolvimento)
Este projeto está preparado para rodar em `Development` utilizando o provider InMemory do EF Core para facilitar testes rápidos sem precisar de SQL Server/LocalDB.

No PowerShell (Windows):

```powershell
# Defina ambiente para Development e rode
$env:ASPNETCORE_ENVIRONMENT = "Development"
dotnet run
```

Abra o Swagger UI (URL mostrado no console, normalmente `http://localhost:5000/swagger`), e utilize o endpoint POST `/api/auth/login` com o JSON:

```json
{
  "username": "admin",
  "password": "TempAdminPassword123!"
}
```

O seeder adiciona esse usuário automaticamente em `Development` (veja `Data/DataSeeder.cs`). Copie o `token` retornado e clique em "Authorize" no Swagger usando:

```
Bearer <token>
```

Agora é possível testar os endpoints protegidos como `/api/vehicles`.

Observações:
- Dados armazenados no provedor InMemory são voláteis: ao reiniciar a aplicação os dados somem.
- O `RateLimitingMiddleware` pode bloquear muitas requisições seguidas do mesmo IP; se necessário, comente `app.UseMiddleware<RateLimitingMiddleware>();` em `Program.cs` para testes locais.

## Preparar Homologação / Produção (passos e ajustes)
Abaixo estão os passos e ajustes recomendados para executar em homologação/produção com um banco relacional (SQL Server). Faça esses passos em uma branch e valide antes de deploy.

1) Configurar connection string segura
- No `appsettings.json` ou, preferencialmente, como uma variável de ambiente (mais seguro), forneça a connection string para o servidor SQL ou outro provedor.

Exemplo `appsettings.json` (produção):

```json
"ConnectionStrings": {
  "DefaultConnection": "Server=sqlserver.example.com;Database=VehicleRegistry;User Id=sa;Password=YourStrongPassword;TrustServerCertificate=True;"
}
```

Ou configure variável de ambiente `ConnectionStrings__DefaultConnection`.

2) Instalar ferramentas EF Core (se necessário)

```powershell
# Ferramenta global (opcional)
dotnet tool install --global dotnet-ef
# Adicione pacote de design para permitir migrations
dotnet add package Microsoft.EntityFrameworkCore.Design
```

3) Criar migrations e aplicar no banco de homolog/prod

```powershell
# Criar migration inicial (faça isso à partir da pasta do projeto)
dotnet ef migrations add InitialCreate
# Aplicar migrations no banco conectado (vai usar a connection string configurada)
dotnet ef database update
```

4) Ajustes recomendados em `Program.cs` para produção
- Mude a validação do token JWT para exigir Issuer, Audience e Validade de tempo:
  - `ValidateIssuer = true`
  - `ValidateAudience = true`
  - `ValidateLifetime = true`
  - Configure `ValidIssuer` e `ValidAudience` a partir das configurações (por exemplo `builder.Configuration["Jwt:Issuer"]`)
- Defina `Jwt:Secret` via variável de ambiente (ex.: `Jwt__Secret`) e use um segredo forte (mínimo 32+ caracteres).
- Remova o seeder automático ou proteja-o para rodar apenas em Development.

Exemplo (alteração sugerida em `Program.cs`):

```csharp
// produção: validar issuer/audience/lifetime
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ValidateLifetime = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(key)
        };
    });

// Fazer seeding apenas em Development
if (app.Environment.IsDevelopment())
{
    using (var scope = app.Services.CreateScope())
    {
        await VehicleRegistryAPI.Data.DataSeeder.SeedAdminUserAsync(scope.ServiceProvider);
    }
}
```

5) Segurança e segredos
- Nunca deixe `Jwt:Secret` explícito em arquivos no repositório. Use:
  - Variáveis de ambiente (ex.: `Jwt__Secret` no Windows PowerShell), ou
  - Azure Key Vault / HashiCorp Vault / outro gerenciador de segredos.

Exemplo em PowerShell para setar JWT secret temporariamente antes de `dotnet run`:

```powershell
$env:Jwt__Secret = "SuperLongAndRandomSecret_ReplaceThis"
$env:ConnectionStrings__DefaultConnection = "Server=...;Database=...;User Id=...;Password=...;"
$env:ASPNETCORE_ENVIRONMENT = "Production"
dotnet run --configuration Release
```

6) Remover dados de desenvolvimento
- Caso você tenha seed com senha padrão, remova esse comportamento ao publicar para produção. Forneça instruções de criação de usuário admin manual ou fluxo seguro de criação.

## Como criar o primeiro usuário / admin
Você tem três opções para criar o admin inicial:

Opção A — (Atualmente configurado) Seeder automático (Development)
- `Data/DataSeeder.cs` já cria o usuário:
  - username: `admin`
  - password: `TempAdminPassword123!`
- O seeder é chamado em `Program.cs` no startup. Em Development isso é conveniente. NÃO deixe isso ativo em produção.

Opção B — Criar manualmente no banco (produção)
1. Após aplicar migrations (`dotnet ef database update`), execute um `INSERT` SQL no banco para adicionar o usuário com senha hasheada.
2. Para gerar o hash da senha de forma compatível, use um utilitário C# curto que chame `PasswordHasher.HashPassword("YourPassword")` (ex.: um console app temporário) ou exponha um endpoint administrativo temporário (não recomendado em produção sem proteção).

Exemplo rápido (PowerShell + curl para um endpoint admin temporário) — RECOMENDADO somente em ambiente protegido e se você expuser um endpoint de administração autenticado por outro mecanismo:

```powershell
# Não fornecido por padrão; alternativa: executar um script C# localmente que usa a biblioteca do projeto para criar o usuário
```

Opção C — Usar o seeder em ambiente controlado
- Você pode permitir que o seeder rode uma única vez em homolog para criar o admin e depois removê-lo ou condicionalizar por uma flag de configuração.

Recomendação prática para produção:
- Não use senha em claro como no seeder. Em vez disso, gere um usuário inicial com senha complexa e troque senha no primeiro login.
- Use migrações e scripts SQL para inserir usuário com hash (ou execute um utilitário local que chame `IPasswordHasher.HashPassword`).

## Endpoints úteis (exemplo)
- POST `/api/auth/login` — login, retorna `token` e `refreshToken`.
- POST `/api/auth/refresh` — refresh usando `refreshToken`.
- GET `/api/vehicles` — requer autorização (Bearer token).

## Como gerar/testar JWT via PowerShell (exemplo)
1. Fazer login e capturar token:

```powershell
$body = @{ username = 'admin'; password = 'TempAdminPassword123!' } | ConvertTo-Json
$response = Invoke-RestMethod -Uri 'https://localhost:5000/api/auth/login' -Method Post -Body $body -ContentType 'application/json'
$token = $response.token

# Usar token para chamar endpoint protegido
Invoke-RestMethod -Uri 'https://localhost:5000/api/vehicles' -Headers @{ Authorization = "Bearer $token" } -Method Get
```

## Ajustes que você pode querer fazer agora (checklist)
- [ ] Mover `Jwt:Secret` para variáveis de ambiente ou vault.
- [ ] Garantir que em `Program.cs` o seeder rode somente em Development.
- [ ] Habilitar e configurar corretamente validações do JWT (Issuer/Audience/Lifetime) para Prod.
- [ ] Adicionar `Microsoft.EntityFrameworkCore.Design` ao `.csproj` se pretende usar `dotnet ef migrations` localmente.
- [ ] Rever política de Rate Limiting para não bloquear testes via Swagger (ou permitir IP localhost durante dev).
- [ ] Remover credenciais de desenvolvimento do repositório.

## Troubleshooting (problemas comuns)
- Erro: "Unable to locate a Local Database Runtime installation" ao usar Swagger:
  - Motivo: app tentou usar LocalDB (SQL Server LocalDB) e o runtime não está instalado.
  - Solução rápida: executar em `Development` (InMemory) ou configurar `DefaultConnection` para um SQL Server acessível.

- Erro EF Core ao traduzir propriedades calculadas (`IsActive`):
  - Motivo: propriedades não mapeadas (somente getters) não são traduzíveis em LINQ para providers como InMemory/SQL.
  - Solução: use campos mapeados (`Revoked == null && Expires > DateTime.UtcNow`) em queries.

## Observações finais
- Este README documenta o estado atual do projeto e recomendações de ajustes para Homolog/Produção.
- Posso aplicar automaticamente algumas mudanças sugeridas (por exemplo: condicionar o seeder para Development apenas, ajustar validação JWT para Prod em `Program.cs`, adicionar `Microsoft.EntityFrameworkCore.Design` ao `.csproj`). Quer que eu faça essas alterações agora?

---
Documentado em: README gerado automaticamente
