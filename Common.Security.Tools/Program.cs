using System.Data.Common;
using System.Text.Json;
using System.Text.Json.Serialization;
using Common.Security.Abstractions;
using Common.Security.Integration;
using Common.Security.Models;
using Microsoft.Data.Sqlite;
using Npgsql;

// Offline, OS-authorized maintenance only. No network listener or application fallback.
try
{
    string Value(string name) { int i=Array.IndexOf(args,name); return i>=0 && i+1<args.Length ? args[i+1] : throw new ArgumentException("Missing "+name); }
    string command=args.FirstOrDefault() ?? "help";
    if(command is not ("import" or "enroll-local" or "recover-local"))
    {
        Console.WriteLine("Common.Security offline maintenance: import|enroll-local|recover-local --provider sqlite|postgres --application APP --manifest PROTECTED_JSON --actor AUDIT_ID [--apply]. Connection: COMMON_SECURITY_CONNECTION. Local passwords: --password-file PROTECTED_FILE. Default: validation only.");
        return 0;
    }
    string application=Value("--application"),actor=Value("--actor");
    string connection=Environment.GetEnvironmentVariable("COMMON_SECURITY_CONNECTION") ?? throw new ArgumentException("COMMON_SECURITY_CONNECTION is required.");
    string provider=Value("--provider");
    Func<DbConnection> factory=provider switch {"sqlite"=>()=>new SqliteConnection(connection),"postgres"=>()=>new NpgsqlConnection(connection),_=>throw new ArgumentException("Provider must be sqlite or postgres.")};
    string manifestPath=Value("--manifest"); RequireProtected(manifestPath);
    var json=new JsonSerializerOptions { PropertyNameCaseInsensitive=true,Converters={new JsonStringEnumConverter()} };
    var rows=JsonSerializer.Deserialize<AccountCreation[]>(File.ReadAllText(manifestPath),json) ?? throw new ArgumentException("An account manifest is required.");
    if(rows.Length==0) throw new ArgumentException("Empty manifest.");
    string? password=null;
    if(command!="import") { var path=Value("--password-file");RequireProtected(path);password=File.ReadAllText(path).TrimEnd('\r','\n');Common.Security.Services.PasswordHasher.Hash(password); }
    if(rows.Select(x=>x.Id).Distinct().Count()!=rows.Length || rows.Any(x=>string.IsNullOrWhiteSpace(x.Id)||string.IsNullOrWhiteSpace(x.LoginName))) throw new ArgumentException("Invalid or duplicate account records.");
    if(command=="import" && rows.Any(x=>x.Identity is null || x.ProviderKind==AuthenticationProviderKind.LocalDatabase)) throw new ArgumentException("Import requires approved immutable external bindings.");
    if(command!="import" && (rows.Length!=1 || rows[0].ProviderKind!=AuthenticationProviderKind.LocalDatabase)) throw new ArgumentException("Local maintenance requires exactly one local account.");
    if(!args.Contains("--apply")) {Console.WriteLine($"Validated {rows.Length} manifest record(s). Database conflicts are checked transactionally during apply. No database writes performed.");return 0;}
    var store=new RelationalAccountStore(factory,application);store.EnsureSchema();
    if(command=="import") store.ImportApprovedAccounts(rows,actor);
    else if(command=="enroll-local") store.Create(rows[0],actor,password);
    else {var account=store.Find(rows[0].Id) ?? throw new ArgumentException("Account not found.");if(account.ProviderKind!=AuthenticationProviderKind.LocalDatabase) throw new ArgumentException("External accounts cannot be converted to local accounts.");store.SetLocalPassword(account.Id,password!,actor);}
    Console.WriteLine($"Applied {command} to {rows.Length} account(s); account audit committed. Application role approval remains application-owned.");return 0;
}
catch(Exception e) when(e is ArgumentException or InvalidOperationException or IOException or DbException)
{
    // Database exception details can contain identifiers or connection information.
    Console.Error.WriteLine("Security maintenance failed: "+e.GetType().Name+". No credentials are printed. Inspect the protected input and database using authorized administrative tools.");return 1;
}
static void RequireProtected(string path)
{
    if(!File.Exists(path)) throw new ArgumentException("Protected input file is missing.");
    if(!OperatingSystem.IsWindows() && (File.GetUnixFileMode(path)&(UnixFileMode.GroupRead|UnixFileMode.GroupWrite|UnixFileMode.GroupExecute|UnixFileMode.OtherRead|UnixFileMode.OtherWrite|UnixFileMode.OtherExecute))!=0)
        throw new ArgumentException("Input files must be accessible only to their owner (chmod 600).");
}
