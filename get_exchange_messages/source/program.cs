using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Exchange.WebServices.Data;

internal sealed class Program
{
    private static int Main(string[] args)
    {
        PatchEwsBuildVersion();

        var baseDir = AppContext.BaseDirectory;
        using var logger = new Logger(Path.Combine(baseDir, "export_messages.log"));
        try
        {
            var configPath = Path.Combine(baseDir, "config.cfg");
            var config = AppConfig.Load(configPath, logger);

            if (config.AllowUntrustedConnections)
            {
                // EWS Managed API internally uses HttpWebRequest, so ServicePointManager
                // is the only way to configure SSL validation for it.
#pragma warning disable SYSLIB0014
                ServicePointManager.ServerCertificateValidationCallback =
                    (sender, certificate, chain, sslPolicyErrors) => true;
#pragma warning restore SYSLIB0014
                logger.Info("Allowing untrusted SSL certificates for EWS connections.");
            }

            var exporter = new MessageExporter(config, logger);
            exporter.Run();
            return 0;
        }
        catch (Exception ex)
        {
            logger.Error($"Fatal error: {ex.Message}", ex);
            return 1;
        }
    }

    /// <summary>
    /// Workaround for EWS Managed API 2.2.0: the static constructor of
    /// <c>EwsUtilities</c> calls <c>FileVersionInfo.GetVersionInfo</c> with
    /// <c>Assembly.GetExecutingAssembly().Location</c>, which returns an empty
    /// string in single-file published apps (or certain modern .NET hosts),
    /// causing a <see cref="TypeInitializationException"/>.
    /// Pre-populate the lazy <c>BuildVersion</c> field via reflection so the
    /// problematic code path is never executed.
    /// </summary>
    private static void PatchEwsBuildVersion()
    {
        try
        {
            var ewsAssembly = typeof(ExchangeService).Assembly;
            var ewsUtilitiesType = ewsAssembly.GetType(
                "Microsoft.Exchange.WebServices.Data.EwsUtilities");
            if (ewsUtilitiesType == null) return;

            var buildVersionField = ewsUtilitiesType.GetField(
                "BuildVersion",
                BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public);
            if (buildVersionField == null) return;

            var lazyMember = buildVersionField.GetValue(null);
            if (lazyMember == null) return;

            var lazyType = lazyMember.GetType();
            var memberField = lazyType.GetField(
                "member", BindingFlags.Instance | BindingFlags.NonPublic);
            var initializedField = lazyType.GetField(
                "initialized", BindingFlags.Instance | BindingFlags.NonPublic);

            if (memberField != null && initializedField != null)
            {
                var version = ewsAssembly.GetName().Version?.ToString() ?? "2.2.0.0";
                memberField.SetValue(lazyMember, version);
                initializedField.SetValue(lazyMember, true);
            }
        }
        catch
        {
            // If patching fails, the original error will surface later.
        }
    }
}

#region Configuration

internal sealed record AppConfig(
    string AutodiscoverUrl,
    string EwsUrl,
    string InputFile,
    string OutputDirectory,
    string SuperAdmin,
    string SuperAdminPassword,
    bool AllowUntrustedConnections,
    TimeZoneInfo ExchangeTimeZone,
    IReadOnlyList<string> Mailboxes)
{
    public static AppConfig Load(string configPath, Logger logger)
    {
        if (!File.Exists(configPath))
        {
            throw new InvalidOperationException($"Config file not found: {configPath}");
        }

        var baseDir = Path.GetDirectoryName(configPath) ?? AppContext.BaseDirectory;
        var settings = ParseConfig(configPath);

        string Get(string key, string fallback = "") =>
            settings.TryGetValue(key, out var v) ? v : fallback;

        var autodiscoverUrl = Get("audiscovery_url");
        var ewsUrl = Get("ews_url");
        var inputFile = Get("input_file", "input_mailboxes.txt");
        var outputDir = Get("output_dir", "output");
        var superAdmin = Get("superadmin");
        var superAdminPass = Get("superadmin_pass");
        var allowUntrusted = ParseBool(Get("allow_untrusted_connections"), false);
        var exchangeTimeZone = ParseTimeZoneShift(Get("exchange_timezone_shift", "+0"));

        if (string.IsNullOrWhiteSpace(superAdmin))
        {
            throw new InvalidOperationException("Parameter 'superadmin' is required.");
        }

        if (string.IsNullOrWhiteSpace(superAdminPass))
        {
            throw new InvalidOperationException("Parameter 'superadmin_pass' is required.");
        }

        if (!Path.IsPathRooted(inputFile))
        {
            inputFile = Path.Combine(baseDir, inputFile);
        }

        if (!File.Exists(inputFile))
        {
            throw new InvalidOperationException($"Input file not found: {inputFile}");
        }

        var mailboxes = File.ReadAllLines(inputFile)
            .Select(l => l.Trim())
            .Where(l => !string.IsNullOrWhiteSpace(l))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (mailboxes.Count == 0)
        {
            throw new InvalidOperationException($"Input file is empty: {inputFile}");
        }

        if (!Path.IsPathRooted(outputDir))
        {
            outputDir = Path.Combine(baseDir, outputDir);
        }

        Directory.CreateDirectory(outputDir);
        logger.Info($"Output directory: {outputDir}");

        return new AppConfig(
            autodiscoverUrl,
            ewsUrl,
            inputFile,
            outputDir,
            superAdmin,
            superAdminPass,
            allowUntrusted,
            exchangeTimeZone,
            mailboxes);
    }

    private static Dictionary<string, string> ParseConfig(string path)
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rawLine in File.ReadAllLines(path))
        {
            var line = rawLine.Trim();
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#", StringComparison.Ordinal))
            {
                continue;
            }

            var separatorIndex = line.IndexOf('=');
            if (separatorIndex <= 0)
            {
                continue;
            }

            var key = line[..separatorIndex].Trim();
            var value = line[(separatorIndex + 1)..].Trim();
            if (!string.IsNullOrEmpty(key))
            {
                dict[key] = value;
            }
        }

        return dict;
    }

    private static bool ParseBool(string value, bool defaultValue)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return defaultValue;
        }

        return value.Equals("true", StringComparison.OrdinalIgnoreCase) ||
               value.Equals("1", StringComparison.Ordinal);
    }

    private static TimeZoneInfo ParseTimeZoneShift(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            value = "+0";
        }

        value = value.Trim();
        if (!value.StartsWith("+", StringComparison.Ordinal) && !value.StartsWith("-", StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "Parameter 'exchange_timezone_shift' must start with '+' or '-' (e.g., +3 or -5).");
        }

        if (!int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var hours))
        {
            throw new InvalidOperationException(
                $"Parameter 'exchange_timezone_shift' has invalid format: '{value}'.");
        }

        var tzName = hours >= 0 ? $"UTC+{hours}" : $"UTC{hours}";
        return TimeZoneInfo.CreateCustomTimeZone(tzName, TimeSpan.FromHours(hours), tzName, tzName);
    }
}

#endregion

#region Message Exporter

internal sealed class MessageExporter
{
    private const int THREAD_COUNT = 4;
    private const int PAGE_SIZE = 1000;
    private const int BATCH_SIZE = 100;

    private readonly AppConfig _config;
    private readonly Logger _logger;

    private readonly PropertySet _itemPropertySet;

    public MessageExporter(AppConfig config, Logger logger)
    {
        _config = config;
        _logger = logger;

        _itemPropertySet = new PropertySet(
            BasePropertySet.IdOnly,
            ItemSchema.Subject,
            ItemSchema.DateTimeSent,
            ItemSchema.DateTimeReceived,
            ItemSchema.Size,
            EmailMessageSchema.From,
            EmailMessageSchema.InternetMessageId);
    }

    public void Run()
    {
        var ewsUri = ResolveEwsUrl();
        var exchangeTimeZone = _config.ExchangeTimeZone;

        _logger.Info($"EWS endpoint: {ewsUri}");
        _logger.Info($"Exchange timezone: {exchangeTimeZone.DisplayName}");
        _logger.Info($"Mailboxes to process: {_config.Mailboxes.Count}");

        var parallelOptions = new ParallelOptions
        {
            MaxDegreeOfParallelism = THREAD_COUNT
        };

        Parallel.ForEach(_config.Mailboxes, parallelOptions, mailbox =>
        {
            using var scope = _logger.BeginMailboxScope(mailbox);
            try
            {
                ProcessMailbox(ewsUri, exchangeTimeZone, mailbox);
            }
            catch (Exception ex)
            {
                _logger.Error(Prefix(mailbox, $"Failed to process mailbox: {ex.Message}"), ex);
            }
        });

        _logger.Info("All mailboxes processed.");
    }

    private void ProcessMailbox(Uri ewsUri, TimeZoneInfo exchangeTimeZone, string mailbox)
    {
        _logger.Info(Prefix(mailbox, "Starting message export"));

        var service = CreateService(ewsUri, exchangeTimeZone);

        // Bind to root folder with delegate access, fall back to impersonation
        FolderId rootFolderId;
        try
        {
            rootFolderId = new FolderId(WellKnownFolderName.MsgFolderRoot, new Mailbox(mailbox));
            Folder.Bind(service, rootFolderId, new PropertySet(FolderSchema.DisplayName));
        }
        catch (ServiceResponseException ex)
        {
            _logger.Warn(Prefix(mailbox,
                $"Delegate access failed ({ex.ErrorCode}: {ex.Message}). Trying impersonation."));
            service.ImpersonatedUserId = new ImpersonatedUserId(ConnectingIdType.SmtpAddress, mailbox);
            rootFolderId = new FolderId(WellKnownFolderName.MsgFolderRoot);
            Folder.Bind(service, rootFolderId, new PropertySet(FolderSchema.DisplayName));
        }

        // Retrieve all folders (deep traversal)
        var allFolders = GetAllFolders(service, rootFolderId, mailbox);
        _logger.Info(Prefix(mailbox, $"Found {allFolders.Count} folders"));

        // Build folder path map (folderId -> "Inbox/Subfolder/...")
        var folderPathMap = BuildFolderPathMap(allFolders, rootFolderId);

        // Create output CSV: <email>_<timestamp>.csv
        var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture);
        var safeEmail = SanitizeFileName(mailbox);
        var csvPath = Path.Combine(_config.OutputDirectory, $"{safeEmail}_{timestamp}.csv");

        using var writer = new StreamWriter(csvPath, false, new UTF8Encoding(true));
        writer.WriteLine("nn;folder;date;from;subject;message-id;size");

        var counter = 0;

        foreach (var folder in allFolders)
        {
            var folderPath = folderPathMap.TryGetValue(folder.Id.UniqueId, out var fp)
                ? fp
                : folder.DisplayName;

            try
            {
                int totalCount;
                try
                {
                    totalCount = folder.TotalCount;
                }
                catch
                {
                    totalCount = -1;
                }

                if (totalCount == 0)
                {
                    continue;
                }

                _logger.Info(Prefix(mailbox, $"Processing folder: {folderPath}" +
                    (totalCount > 0 ? $" ({totalCount} items)" : "")));

                ProcessFolder(service, folder, folderPath, writer, ref counter, mailbox, exchangeTimeZone);
            }
            catch (Exception ex)
            {
                _logger.Error(Prefix(mailbox, $"Error processing folder '{folderPath}': {ex.Message}"));
            }
        }

        _logger.Info(Prefix(mailbox, $"Export complete. {counter} messages written to {csvPath}"));
    }

    private List<Folder> GetAllFolders(ExchangeService service, FolderId rootFolderId, string mailbox)
    {
        var allFolders = new List<Folder>();

        var folderView = new FolderView(PAGE_SIZE)
        {
            Traversal = FolderTraversal.Deep,
            PropertySet = new PropertySet(
                BasePropertySet.IdOnly,
                FolderSchema.DisplayName,
                FolderSchema.ParentFolderId,
                FolderSchema.TotalCount)
        };

        FindFoldersResults result;
        do
        {
            result = service.FindFolders(rootFolderId, folderView);
            allFolders.AddRange(result.Folders);
            folderView.Offset += result.Folders.Count;
        } while (result.MoreAvailable);

        return allFolders;
    }

    private Dictionary<string, string> BuildFolderPathMap(List<Folder> folders, FolderId rootFolderId)
    {
        var rootUniqueId = rootFolderId.UniqueId;

        // Map folderId -> (displayName, parentFolderId)
        var infoMap = new Dictionary<string, (string DisplayName, string? ParentId)>();
        foreach (var f in folders)
        {
            string? parentId = null;
            try
            {
                parentId = f.ParentFolderId?.UniqueId;
            }
            catch
            {
                // ParentFolderId might not be loaded
            }

            infoMap[f.Id.UniqueId] = (f.DisplayName ?? "(unknown)", parentId);
        }

        // Build full path for each folder
        var pathMap = new Dictionary<string, string>();
        foreach (var f in folders)
        {
            var parts = new List<string>();
            var currentId = f.Id.UniqueId;
            var visited = new HashSet<string>();

            while (currentId != null && infoMap.TryGetValue(currentId, out var info))
            {
                if (!visited.Add(currentId))
                {
                    break; // circular reference guard
                }

                parts.Add(info.DisplayName);
                currentId = info.ParentId;

                // Stop at root
                if (currentId == rootUniqueId)
                {
                    break;
                }
            }

            parts.Reverse();
            pathMap[f.Id.UniqueId] = parts.Count > 0 ? string.Join("/", parts) : f.DisplayName ?? "";
        }

        return pathMap;
    }

    private void ProcessFolder(
        ExchangeService service,
        Folder folder,
        string folderPath,
        StreamWriter writer,
        ref int counter,
        string mailbox,
        TimeZoneInfo exchangeTimeZone)
    {
        var offset = 0;
        bool moreItems;

        do
        {
            var view = new ItemView(PAGE_SIZE, offset)
            {
                PropertySet = new PropertySet(BasePropertySet.IdOnly)
            };

            FindItemsResults<Item> findResults;
            try
            {
                findResults = service.FindItems(folder.Id, view);
            }
            catch (Exception ex)
            {
                _logger.Error(Prefix(mailbox, $"FindItems failed in '{folderPath}' at offset {offset}: {ex.Message}"));
                break;
            }

            if (findResults.Items.Count == 0)
            {
                break;
            }

            // Batch load properties
            var loaded = BatchLoadItems(service, findResults.Items.ToList(), mailbox, folderPath);

            foreach (var item in loaded)
            {
                counter++;
                var line = FormatCsvLine(counter, folderPath, item, exchangeTimeZone);
                writer.WriteLine(line);
            }

            offset += findResults.Items.Count;
            moreItems = findResults.MoreAvailable;

        } while (moreItems);
    }

    private List<Item> BatchLoadItems(
        ExchangeService service,
        List<Item> items,
        string mailbox,
        string folderContext)
    {
        var loaded = new List<Item>(items.Count);

        for (var batchStart = 0; batchStart < items.Count; batchStart += BATCH_SIZE)
        {
            var batch = items.Skip(batchStart).Take(BATCH_SIZE).ToList();
            ServiceResponseCollection<ServiceResponse>? responses = null;

            try
            {
                responses = service.LoadPropertiesForItems(batch, _itemPropertySet);
            }
            catch (ServiceRequestException ex)
            {
                _logger.Warn(Prefix(mailbox,
                    $"Batch load failed in '{folderContext}' ({batchStart}-{batchStart + batch.Count - 1}): {ex.Message}"));
            }
            catch (Exception ex)
            {
                _logger.Warn(Prefix(mailbox,
                    $"Batch load error in '{folderContext}' ({batchStart}-{batchStart + batch.Count - 1}): {ex.Message}"));
            }

            if (responses == null)
            {
                continue;
            }

            for (var i = 0; i < responses.Count; i++)
            {
                if (responses[i].Result == ServiceResult.Success)
                {
                    loaded.Add(batch[i]);
                }
                else
                {
                    _logger.Debug(Prefix(mailbox,
                        $"Skipping item in '{folderContext}': {responses[i].ErrorCode} - {responses[i].ErrorMessage}"));
                }
            }
        }

        return loaded;
    }

    private static string FormatCsvLine(int number, string folderPath, Item item, TimeZoneInfo exchangeTimeZone)
    {
        // Subject
        var subject = string.Empty;
        try
        {
            subject = MimeDecoder.DecodeEncodedWords(item.Subject ?? string.Empty);
        }
        catch
        {
            // property not available
        }

        // From
        var from = string.Empty;
        try
        {
            if (item is EmailMessage email && email.From != null)
            {
                var name = MimeDecoder.DecodeEncodedWords(email.From.Name ?? string.Empty);
                var address = email.From.Address ?? string.Empty;

                from = !string.IsNullOrWhiteSpace(name)
                    ? $"{name} <{address}>"
                    : address;
            }
        }
        catch
        {
            // non-email item or property not available
        }

        // Date (DateTimeSent = Date header; fallback to DateTimeReceived)
        var dateStr = string.Empty;
        try
        {
            dateStr = FormatDateWithOffset(item.DateTimeSent, exchangeTimeZone);
        }
        catch
        {
            try
            {
                dateStr = FormatDateWithOffset(item.DateTimeReceived, exchangeTimeZone);
            }
            catch
            {
                // no date available
            }
        }

        // Message-ID
        var messageId = string.Empty;
        try
        {
            if (item is EmailMessage emailMsg)
            {
                messageId = emailMsg.InternetMessageId ?? string.Empty;
            }
        }
        catch
        {
            // property not available
        }

        // Size (bytes, includes attachments)
        var sizeStr = string.Empty;
        try
        {
            sizeStr = item.Size.ToString(CultureInfo.InvariantCulture);
        }
        catch
        {
            // property not available
        }

        return string.Join(";",
            number.ToString(CultureInfo.InvariantCulture),
            CsvEscape(folderPath),
            CsvEscape(dateStr),
            CsvEscape(from),
            CsvEscape(subject),
            CsvEscape(messageId),
            CsvEscape(sizeStr));
    }

    private static string FormatDateWithOffset(DateTime dt, TimeZoneInfo tz)
    {
        if (dt.Kind == DateTimeKind.Utc)
        {
            dt = TimeZoneInfo.ConvertTimeFromUtc(dt, tz);
        }

        var offset = tz.GetUtcOffset(dt);
        var sign = offset >= TimeSpan.Zero ? "+" : "-";
        var absOffset = offset.Duration();
        return dt.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)
            + $" {sign}{absOffset.Hours:D2}{absOffset.Minutes:D2}";
    }

    /// <summary>
    /// Escapes a value for semicolon-delimited CSV.
    /// Wraps in double quotes if the value contains ; or " or newlines.
    /// </summary>
    private static string CsvEscape(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        if (value.IndexOfAny(new[] { ';', '"', '\n', '\r' }) >= 0)
        {
            return "\"" + value.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
        }

        return value;
    }

    #region EWS Service helpers

    private Uri ResolveEwsUrl()
    {
        if (!string.IsNullOrWhiteSpace(_config.AutodiscoverUrl))
        {
            try
            {
                var autodiscover = new AutodiscoverService(ExchangeVersion.Exchange2013)
                {
                    Credentials = new WebCredentials(_config.SuperAdmin, _config.SuperAdminPassword),
                    EnableScpLookup = false,
                };

                autodiscover.Url = new Uri(_config.AutodiscoverUrl);
                _logger.Info($"Trying autodiscover at {_config.AutodiscoverUrl}");

                var response = autodiscover.GetUserSettings(
                    _config.SuperAdmin,
                    new[]
                    {
                        UserSettingName.InternalEwsUrl,
                        UserSettingName.ExternalEwsUrl
                    });

                if (response.ErrorCode == AutodiscoverErrorCode.NoError)
                {
                    var urlCandidate =
                        response.Settings.TryGetValue(UserSettingName.InternalEwsUrl, out var internalUrl)
                            ? internalUrl as string
                            : response.Settings.TryGetValue(UserSettingName.ExternalEwsUrl, out var externalUrl)
                                ? externalUrl as string
                                : null;

                    if (!string.IsNullOrWhiteSpace(urlCandidate))
                    {
                        _logger.Info($"Autodiscover returned EWS url: {urlCandidate}");
                        return new Uri(urlCandidate);
                    }
                }

                _logger.Warn("Autodiscover did not return a usable EWS url, falling back to ews_url.");
            }
            catch (Exception ex)
            {
                _logger.Warn($"Autodiscover failed: {ex.Message}. Falling back to ews_url.");
            }
        }

        if (string.IsNullOrWhiteSpace(_config.EwsUrl))
        {
            throw new InvalidOperationException("Neither autodiscovery nor ews_url provided a valid endpoint.");
        }

        return new Uri(_config.EwsUrl);
    }

    private ExchangeService CreateService(Uri ewsUri, TimeZoneInfo exchangeTimeZone)
    {
        return new ExchangeService(ExchangeVersion.Exchange2013, exchangeTimeZone)
        {
            Credentials = new WebCredentials(_config.SuperAdmin, _config.SuperAdminPassword),
            Url = ewsUri,
            TraceEnabled = false,
        };
    }

    #endregion

    private static string SanitizeFileName(string name)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var cleaned = new string(name.Select(ch => invalid.Contains(ch) ? '_' : ch).ToArray());
        return string.IsNullOrWhiteSpace(cleaned) ? "mailbox" : cleaned;
    }

    private static string Prefix(string mailbox, string message) => $"[{mailbox}] {message}";
}

#endregion

#region MIME Encoded-Word Decoder

/// <summary>
/// Decodes RFC 2047 encoded-word sequences (=?charset?encoding?text?=) that may appear
/// in Subject or From fields. EWS usually returns decoded values, but this is a safety net.
/// </summary>
internal static class MimeDecoder
{
    private static readonly Regex EncodedWordPattern = new(
        @"=\?(?<charset>[^?]+)\?(?<encoding>[BbQq])\?(?<text>[^?]+)\?=",
        RegexOptions.Compiled);

    public static string DecodeEncodedWords(string input)
    {
        if (string.IsNullOrEmpty(input))
        {
            return input;
        }

        // Remove soft line breaks between adjacent encoded words
        var cleaned = Regex.Replace(input, @"\?=\s+=\?", "?==?");

        return EncodedWordPattern.Replace(cleaned, match =>
        {
            var charset = match.Groups["charset"].Value;
            var encoding = match.Groups["encoding"].Value.ToUpperInvariant();
            var encodedText = match.Groups["text"].Value;

            try
            {
                var enc = Encoding.GetEncoding(charset);
                byte[] bytes;

                if (encoding == "B")
                {
                    bytes = Convert.FromBase64String(encodedText);
                }
                else // Q-encoding
                {
                    bytes = DecodeQuotedPrintableWord(encodedText);
                }

                return enc.GetString(bytes);
            }
            catch
            {
                return match.Value; // return original on failure
            }
        });
    }

    /// <summary>
    /// Decodes Q-encoded text per RFC 2047 (underscores = spaces, =XX = hex byte).
    /// </summary>
    private static byte[] DecodeQuotedPrintableWord(string input)
    {
        var bytes = new List<byte>(input.Length);

        for (var i = 0; i < input.Length; i++)
        {
            if (input[i] == '_')
            {
                bytes.Add((byte)' ');
            }
            else if (input[i] == '=' && i + 2 < input.Length)
            {
                var hex = input.Substring(i + 1, 2);
                if (byte.TryParse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var b))
                {
                    bytes.Add(b);
                    i += 2;
                }
                else
                {
                    bytes.Add((byte)input[i]);
                }
            }
            else
            {
                bytes.Add((byte)input[i]);
            }
        }

        return bytes.ToArray();
    }
}

#endregion

#region Logger

internal sealed class Logger : IDisposable
{
    private readonly object _gate = new();
    private readonly StreamWriter _writer;
    private readonly AsyncLocal<string?> _mailboxPrefix = new();

    public Logger(string logPath)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(logPath) ?? ".");
        _writer = new StreamWriter(File.Open(logPath, FileMode.Append, FileAccess.Write, FileShare.Read))
        {
            AutoFlush = true
        };
    }

    public void Info(string message) => Write("INFO", message);
    public void Warn(string message) => Write("WARN", message);
    public void Debug(string message) => Write("DEBUG", message);

    public void Error(string message, Exception? ex = null)
    {
        var details = ex == null ? message : $"{message}. Exception: {ex}";
        Write("ERROR", details);
    }

    private void Write(string level, string message)
    {
        var line = $"{DateTime.UtcNow:o} [{level}] {Format(message)}";
        lock (_gate)
        {
            Console.WriteLine(line);
            _writer.WriteLine(line);
        }
    }

    public IDisposable BeginMailboxScope(string mailbox)
    {
        var previous = _mailboxPrefix.Value;
        _mailboxPrefix.Value = $"[{mailbox}] ";
        return new MailboxScope(this, previous);
    }

    private string Format(string message)
    {
        var prefix = _mailboxPrefix.Value;
        if (string.IsNullOrEmpty(prefix) || message.StartsWith(prefix, StringComparison.Ordinal))
        {
            return message;
        }

        return prefix + message;
    }

    public void Dispose()
    {
        _writer.Dispose();
    }

    private sealed class MailboxScope : IDisposable
    {
        private readonly Logger _logger;
        private readonly string? _previous;

        public MailboxScope(Logger logger, string? previous)
        {
            _logger = logger;
            _previous = previous;
        }

        public void Dispose()
        {
            _logger._mailboxPrefix.Value = _previous;
        }
    }
}

#endregion
