using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Automation;
using System.Windows.Forms;
using Microsoft.Win32;

[assembly: System.Reflection.AssemblyTitle("Kiro Auto Approve")]
[assembly: System.Reflection.AssemblyDescription("Automatic Kiro IDE AI authorization")]
[assembly: System.Reflection.AssemblyVersion("1.1.0.0")]
[assembly: System.Reflection.AssemblyFileVersion("1.1.0.0")]

namespace KiroAutoApprove
{
    internal static class I18n
    {
        public static readonly bool Chinese = UseChinese();
        private static bool UseChinese()
        {
            string requested = Environment.GetEnvironmentVariable("KIRO_AUTO_APPROVE_LANG");
            if (String.Equals(requested, "zh", StringComparison.OrdinalIgnoreCase)) return true;
            if (String.Equals(requested, "en", StringComparison.OrdinalIgnoreCase)) return false;
            return String.Equals(CultureInfo.CurrentUICulture.TwoLetterISOLanguageName,
                "zh", StringComparison.OrdinalIgnoreCase);
        }
        public static string T(string zh, string en) { return Chinese ? zh : en; }
    }

    internal static class Program
    {
        private static Mutex instanceMutex;

        [STAThread]
        private static void Main()
        {
            bool created;
            instanceMutex = new Mutex(true, "Local\\KiroAutoApprove.Desktop", out created);
            if (!created)
            {
                MessageBox.Show(I18n.T("Kiro 自动授权已经在运行，请查看系统托盘。",
                    "Kiro Auto Approve is already running. Check the system tray."),
                    I18n.T("Kiro 自动授权", "Kiro Auto Approve"));
                return;
            }
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            try { Application.Run(new MainForm()); }
            finally
            {
                instanceMutex.ReleaseMutex();
                instanceMutex.Dispose();
            }
        }
    }

    internal sealed class AuthorizationRecord
    {
        public string Timestamp { get; set; }
        public string Decision { get; set; }
        public string Reason { get; set; }
        public int ProcessId { get; set; }
        public string WindowTitle { get; set; }
        public string Button { get; set; }
        public string Prompt { get; set; }
        public string Signature { get; set; }
        public string Error { get; set; }
        public string Detection { get; set; }
        public string ActionMethod { get; set; }
        public bool Verified { get; set; }
    }

    internal sealed class AuditStore
    {
        private readonly object sync = new object();
        private readonly JavaScriptSerializer serializer = new JavaScriptSerializer();
        public string LogPath { get; private set; }

        public AuditStore()
        {
            string directory = Path.Combine(Environment.GetFolderPath(
                Environment.SpecialFolder.LocalApplicationData), "KiroAutoApprove");
            Directory.CreateDirectory(directory);
            LogPath = Path.Combine(directory, "authorization-history.jsonl");
        }

        public void Append(AuthorizationRecord record)
        {
            lock (sync)
                File.AppendAllText(LogPath, serializer.Serialize(record) + Environment.NewLine,
                    new UTF8Encoding(false));
        }

        public List<AuthorizationRecord> ReadAll()
        {
            List<AuthorizationRecord> records = new List<AuthorizationRecord>();
            lock (sync)
            {
                if (!File.Exists(LogPath)) return records;
                foreach (string line in File.ReadLines(LogPath, Encoding.UTF8))
                {
                    try
                    {
                        if (String.IsNullOrWhiteSpace(line)) continue;
                        AuthorizationRecord item = serializer.Deserialize<AuthorizationRecord>(line);
                        if (item != null) records.Add(item);
                    }
                    catch { }
                }
            }
            records.Reverse();
            return records;
        }
    }

    internal sealed class KiroWatcher : IDisposable
    {
        private delegate bool EnumWindowsProc(IntPtr hwnd, IntPtr lParam);
        [DllImport("user32.dll")] private static extern bool EnumWindows(EnumWindowsProc callback, IntPtr lParam);
        [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint processId);
        [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr hwnd);
        [DllImport("user32.dll")] private static extern bool SetForegroundWindow(IntPtr hwnd);
        [DllImport("user32.dll")] private static extern void mouse_event(uint flags, uint dx, uint dy, uint data, UIntPtr extraInfo);
        private const uint MouseLeftDown = 0x0002;
        private const uint MouseLeftUp = 0x0004;

        private readonly AuditStore store;
        private readonly object recentLock = new object();
        private readonly Dictionary<string, DateTime> recent = new Dictionary<string, DateTime>();
        private readonly Dictionary<string, DateTime> recentFailureLogs = new Dictionary<string, DateTime>();
        private CancellationTokenSource cancellation;
        private Task worker;
        private volatile bool authorizeAll = true;
        private volatile bool protectHighRisk;

        private static readonly Regex[] ContextPatterns = new Regex[] {
            Rx("permission needed"),
            Rx("needs? you"),
            Rx("need(s)? your input"),
            Rx("your approval is required to continue"),
            Rx("requires? (your )?(approval|permission)"),
            Rx("wants to (run|execute|use|access)"),
            Rx("(allow|approve) (this |the )?(command|action|tool|request)"),
            Rx("you can still allow or deny"),
            Rx("allow or deny (it|this) for this run"),
            Rx("授权"), Rx("需要.{0,8}(批准|允许|确认)"), Rx("允许.{0,8}(命令|操作|工具|请求)")
        };

        private static readonly Regex[] StrongPermissionPatterns = new Regex[] {
            Rx("permission needed"), Rx("session(s)? need your input"),
            Rx("needs? you\\s*\\(\\d+\\)"), Rx("当前.{0,8}(需要|等待).{0,8}(批准|允许|授权)")
        };

        private static readonly Regex[] DangerousPatterns = new Regex[] {
            Rx(@"\brm\s+(-[^\r\n]*r[^\r\n]*f|--recursive)"),
            Rx(@"\bRemove-Item\b[^\r\n]*(?:-Recurse|-Force)"),
            Rx(@"\b(del|erase|rmdir|rd)\b[^\r\n]*(?:/s|/q)"),
            Rx(@"\b(format|diskpart|cipher\s+/w|bcdedit)\b"),
            Rx(@"\b(shutdown|Stop-Computer|Restart-Computer)\b"),
            Rx(@"\bgit\s+(reset\s+--hard|clean\s+-[^\r\n]*f)"),
            Rx(@"\bDROP\s+(DATABASE|SCHEMA|TABLE)\b"),
            Rx(@"\bTRUNCATE\s+TABLE\b")
        };

        public event Action<AuthorizationRecord> RecordCreated;
        public event Action<string> StatusChanged;
        public bool IsRunning { get { return worker != null && !worker.IsCompleted; } }
        public bool AuthorizeAll { get { return authorizeAll; } set { authorizeAll = value; } }
        public bool ProtectHighRisk { get { return protectHighRisk; } set { protectHighRisk = value; } }

        public KiroWatcher(AuditStore auditStore) { store = auditStore; }

        private static Regex Rx(string pattern)
        {
            return new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
                TimeSpan.FromMilliseconds(200));
        }

        public void Start()
        {
            if (IsRunning) return;
            cancellation = new CancellationTokenSource();
            worker = Task.Factory.StartNew(delegate { Loop(cancellation.Token); },
                cancellation.Token, TaskCreationOptions.LongRunning, TaskScheduler.Default);
            SendStatus(I18n.T("正在监听 Kiro 授权请求", "Watching for Kiro authorization requests"));
        }

        public void Stop()
        {
            if (cancellation != null) cancellation.Cancel();
            if (worker != null) try { worker.Wait(2500); } catch { }
            worker = null;
            if (cancellation != null) cancellation.Dispose();
            cancellation = null;
            SendStatus(I18n.T("监听已暂停", "Watching paused"));
        }

        private void Loop(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                try { ScanWindows(); }
                catch (Exception ex) { SendStatus(I18n.T("扫描异常：", "Scan error: ") + OneLine(ex.Message, 100)); }
                token.WaitHandle.WaitOne(350);
            }
        }

        private void ScanWindows()
        {
            Dictionary<int, Process> processes = new Dictionary<int, Process>();
            foreach (Process process in Process.GetProcessesByName("Kiro")) processes[process.Id] = process;
            HashSet<IntPtr> handles = new HashSet<IntPtr>();
            EnumWindows(delegate(IntPtr hwnd, IntPtr unused)
            {
                uint pid;
                GetWindowThreadProcessId(hwnd, out pid);
                if (processes.ContainsKey((int)pid) && IsWindowVisible(hwnd)) handles.Add(hwnd);
                return true;
            }, IntPtr.Zero);

            foreach (Process process in processes.Values)
                if (process.MainWindowHandle != IntPtr.Zero) handles.Add(process.MainWindowHandle);

            foreach (IntPtr handle in handles)
            {
                uint pid;
                GetWindowThreadProcessId(handle, out pid);
                Process process;
                if (!processes.TryGetValue((int)pid, out process)) continue;
                try { ScanWindow(process, handle); }
                catch (Exception ex) { LogWindowFailure(process, handle, "window-scan-failed", ex.Message); }
            }
            foreach (Process process in processes.Values) process.Dispose();
        }

        private void ScanWindow(Process process, IntPtr handle)
        {
            AutomationElement root;
            try { root = AutomationElement.FromHandle(handle); }
            catch (Exception ex) { LogWindowFailure(process, handle, "uia-root-failed", ex.Message); return; }
            if (root == null) return;

            AutomationElementCollection elements;
            try
            {
                elements = root.FindAll(TreeScope.Descendants, Condition.TrueCondition);
            }
            catch (Exception ex) { LogWindowFailure(process, handle, "uia-tree-failed", ex.Message); return; }

            List<AutomationElement> candidates = new List<AutomationElement>();
            StringBuilder rootTextBuilder = new StringBuilder();
            for (int i = 0; i < elements.Count; i++)
            {
                try
                {
                    string name = OneLine(elements[i].Current.Name, 300);
                    if (!String.IsNullOrWhiteSpace(name) && rootTextBuilder.Length < 12000)
                        rootTextBuilder.Append(name).Append(' ');
                    if (IsAllowButton(name) && !IsPersistentButton(name) && IsActionableCandidate(elements[i]))
                        candidates.Add(elements[i]);
                }
                catch { }
            }

            string rootText = OneLine(rootTextBuilder.ToString(), 12000);
            string strongSignal = Matches(rootText, StrongPermissionPatterns);
            if (candidates.Count == 0 && strongSignal != null)
            {
                string signature = Hash(process.Id + "|" + handle + "|no-allow|" + OneLine(rootText, 1200));
                if (ShouldLogFailure(signature, 15))
                {
                    AuthorizationRecord unresolved = NewRecord(process, root, "", rootText, signature);
                    unresolved.Decision = "unresolved";
                    unresolved.Reason = I18n.T("识别到授权请求，但未找到可点击的 Allow 控件",
                        "Authorization request detected, but no actionable Allow control was found");
                    unresolved.Detection = "window-signal:" + strongSignal;
                    Save(unresolved);
                    SendStatus(I18n.T("检测到授权请求，但未找到 Allow 控件（已记录）",
                        "Authorization detected without an Allow control (recorded)"));
                }
                return;
            }

            foreach (AutomationElement button in candidates)
            {
                string buttonName;
                try { buttonName = OneLine(button.Current.Name, 100); } catch { continue; }
                string detection;
                string context = FindContext(button, out detection);
                if (String.IsNullOrEmpty(context) && strongSignal != null)
                {
                    context = rootText;
                    detection = "window-signal:" + strongSignal;
                }

                if (String.IsNullOrEmpty(context))
                {
                    string nearby = NearestText(button);
                    string unmatchedSignature = Hash(process.Id + "|" + handle + "|unmatched|" + buttonName + "|" + nearby);
                    if (ShouldLogFailure(unmatchedSignature, 15))
                    {
                        AuthorizationRecord unmatched = NewRecord(process, root, buttonName, nearby, unmatchedSignature);
                        unmatched.Decision = "unmatched";
                        unmatched.Reason = I18n.T("发现 Allow 候选，但未识别到授权上下文",
                            "Allow candidate found without recognized authorization context");
                        unmatched.Detection = "allow-candidate-only";
                        Save(unmatched);
                        SendStatus(I18n.T("发现 Allow 候选但上下文未匹配（已记录）",
                            "Allow candidate context did not match (recorded)"));
                    }
                    continue;
                }

                string signature = Hash(process.Id + "|" + handle + "|" + buttonName + "|" + context);
                if (WasRecentlyHandled(signature)) continue;

                AuthorizationRecord record = NewRecord(process, root, buttonName, context, signature);
                record.Detection = detection;

                if (!authorizeAll)
                {
                    record.Decision = "skipped";
                    record.Reason = I18n.T("完整授权已关闭", "Full authorization is disabled");
                    MarkHandled(signature);
                    Save(record);
                    continue;
                }

                string danger = protectHighRisk ? Matches(context, DangerousPatterns) : null;
                if (danger != null)
                {
                    record.Decision = "blocked";
                    record.Reason = I18n.T("高风险保护：", "High-risk protection: ") + danger;
                    MarkHandled(signature);
                    Save(record);
                    continue;
                }

                string actionMethod;
                string actionError;
                if (TryApprove(button, handle, out actionMethod, out actionError))
                {
                    record.ActionMethod = actionMethod;
                    record.Verified = VerifyHandled(button, context);
                    if (record.Verified)
                    {
                        record.Decision = "approved";
                        record.Reason = I18n.T("完整授权（" + actionMethod + "，已确认）",
                            "Full authorization (" + actionMethod + ", verified)");
                        MarkHandled(signature);
                        Save(record);
                        SendStatus(I18n.T("已自动授权并确认：", "Automatically approved and verified: ") + OneLine(context, 75));
                        break;
                    }
                    actionError = I18n.T("已调用 " + actionMethod + "，但授权卡片仍然存在",
                        actionMethod + " was invoked, but the authorization card is still present");
                }

                record.Decision = "error";
                record.Reason = I18n.T("授权动作失败或未确认，程序会继续重试",
                    "Authorization failed or could not be verified; retrying");
                record.ActionMethod = actionMethod;
                record.Error = OneLine(actionError, 500);
                if (ShouldLogFailure(signature + "|action", 8)) Save(record);
                SendStatus(I18n.T("授权失败，正在重试（已记录）",
                    "Authorization failed; retrying (recorded)"));
            }
        }

        private AuthorizationRecord NewRecord(Process process, AutomationElement root, string button,
            string prompt, string signature)
        {
            string title = "";
            try { title = root.Current.Name; } catch { }
            if (String.IsNullOrWhiteSpace(title)) try { title = process.MainWindowTitle; } catch { }
            return new AuthorizationRecord {
                Timestamp = DateTimeOffset.Now.ToString("o"), ProcessId = process.Id,
                WindowTitle = OneLine(title, 200), Button = button,
                Prompt = OneLine(prompt, 1200), Signature = signature
            };
        }

        private string FindContext(AutomationElement button, out string detection)
        {
            detection = null;
            AutomationElement element = button;
            TreeWalker walker = TreeWalker.ControlViewWalker;
            for (int depth = 0; depth <= 12 && element != null; depth++)
            {
                string text = ElementText(element, 350, 7000);
                string marker = Matches(text, ContextPatterns);
                if (marker != null) { detection = "text:" + marker; return text; }
                if (HasDenyPeer(element)) { detection = "structure:allow-deny-pair"; return text; }
                try { element = walker.GetParent(element); } catch { element = null; }
            }
            return null;
        }

        private static bool HasDenyPeer(AutomationElement container)
        {
            try
            {
                AutomationElementCollection descendants = container.FindAll(TreeScope.Descendants,
                    new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Button));
                bool allow = false, deny = false;
                for (int i = 0; i < descendants.Count; i++)
                {
                    string name = OneLine(descendants[i].Current.Name, 80).ToLowerInvariant();
                    if (IsAllowButton(name)) allow = true;
                    if (name == "deny" || name == "reject" || name == "拒绝" || name == "不允许") deny = true;
                }
                return allow && deny;
            }
            catch { return false; }
        }

        private static string NearestText(AutomationElement element)
        {
            string best = "";
            TreeWalker walker = TreeWalker.ControlViewWalker;
            for (int depth = 0; depth < 7 && element != null; depth++)
            {
                string text = ElementText(element, 150, 2500);
                if (text.Length > best.Length) best = text;
                try { element = walker.GetParent(element); } catch { element = null; }
            }
            return best;
        }

        private static string ElementText(AutomationElement root, int maxElements, int maxChars)
        {
            StringBuilder text = new StringBuilder();
            try
            {
                if (!String.IsNullOrWhiteSpace(root.Current.Name)) text.Append(root.Current.Name).Append(' ');
                AutomationElementCollection elements = root.FindAll(TreeScope.Descendants, Condition.TrueCondition);
                for (int i = 0; i < Math.Min(elements.Count, maxElements) && text.Length < maxChars; i++)
                {
                    try
                    {
                        string name = elements[i].Current.Name;
                        if (!String.IsNullOrWhiteSpace(name)) text.Append(name).Append(' ');
                    }
                    catch { }
                }
            }
            catch { }
            return OneLine(text.ToString(), maxChars);
        }

        private bool WasRecentlyHandled(string signature)
        {
            lock (recentLock)
            {
                DateTime now = DateTime.UtcNow;
                foreach (string key in recent.Where(delegate(KeyValuePair<string, DateTime> x)
                    { return (now - x.Value).TotalSeconds > 90; }).Select(delegate(KeyValuePair<string, DateTime> x)
                    { return x.Key; }).ToList()) recent.Remove(key);
                DateTime previous;
                return recent.TryGetValue(signature, out previous) && (now - previous).TotalSeconds < 30;
            }
        }

        private void MarkHandled(string signature)
        {
            lock (recentLock) recent[signature] = DateTime.UtcNow;
        }

        private bool ShouldLogFailure(string signature, int cooldownSeconds)
        {
            lock (recentLock)
            {
                DateTime now = DateTime.UtcNow;
                foreach (string key in recentFailureLogs.Where(delegate(KeyValuePair<string, DateTime> x)
                    { return (now - x.Value).TotalMinutes > 5; }).Select(delegate(KeyValuePair<string, DateTime> x)
                    { return x.Key; }).ToList()) recentFailureLogs.Remove(key);
                DateTime previous;
                if (recentFailureLogs.TryGetValue(signature, out previous) &&
                    (now - previous).TotalSeconds < cooldownSeconds) return false;
                recentFailureLogs[signature] = now;
                return true;
            }
        }

        private static bool TryApprove(AutomationElement button, IntPtr windowHandle,
            out string method, out string error)
        {
            List<string> errors = new List<string>();
            method = null;
            try
            {
                object pattern;
                if (button.TryGetCurrentPattern(InvokePattern.Pattern, out pattern))
                {
                    ((InvokePattern)pattern).Invoke();
                    method = "UIA Invoke";
                    error = null;
                    return true;
                }
            }
            catch (Exception ex) { errors.Add("Invoke=" + OneLine(ex.Message, 160)); }

            try
            {
                System.Windows.Point point;
                if (!button.TryGetClickablePoint(out point)) throw new InvalidOperationException(
                    I18n.T("没有可点击坐标", "No clickable point is available"));
                System.Drawing.Point oldPosition = Cursor.Position;
                SetForegroundWindow(windowHandle);
                Cursor.Position = new System.Drawing.Point((int)Math.Round(point.X), (int)Math.Round(point.Y));
                mouse_event(MouseLeftDown, 0, 0, 0, UIntPtr.Zero);
                mouse_event(MouseLeftUp, 0, 0, 0, UIntPtr.Zero);
                Cursor.Position = oldPosition;
                method = "Validated Coordinate";
                error = null;
                return true;
            }
            catch (Exception ex) { errors.Add("Coordinate=" + OneLine(ex.Message, 160)); }

            error = errors.Count == 0 ? I18n.T("控件不支持任何点击方式", "The control supports no click method") : String.Join("; ", errors);
            return false;
        }

        private bool VerifyHandled(AutomationElement originalButton, string originalContext)
        {
            string originalHash = Hash(OneLine(originalContext, 7000));
            for (int attempt = 0; attempt < 6; attempt++)
            {
                Thread.Sleep(160);
                try
                {
                    if (originalButton.Current.IsOffscreen) return true;
                    string detection;
                    string currentContext = FindContext(originalButton, out detection);
                    if (String.IsNullOrEmpty(currentContext)) return true;
                    if (Hash(OneLine(currentContext, 7000)) != originalHash) return true;
                }
                catch (ElementNotAvailableException) { return true; }
                catch (InvalidOperationException) { return true; }
            }
            return false;
        }

        private void LogWindowFailure(Process process, IntPtr handle, string reason, string error)
        {
            string signature = Hash(process.Id + "|" + handle + "|" + reason + "|" + error);
            if (!ShouldLogFailure(signature, 30)) return;
            AuthorizationRecord record = new AuthorizationRecord {
                Timestamp = DateTimeOffset.Now.ToString("o"), Decision = "error", Reason = reason,
                ProcessId = process.Id, WindowTitle = OneLine(process.MainWindowTitle, 200),
                Prompt = "", Button = "", Signature = signature, Error = OneLine(error, 500),
                Detection = "window-enumeration", Verified = false
            };
            Save(record);
        }

        private static bool IsAllowButton(string name)
        {
            string n = name.Trim().ToLowerInvariant();
            return n == "allow" || n.StartsWith("allow once") || n.StartsWith("allow this time") ||
                n.StartsWith("allow for this run") || n == "approve" || n.StartsWith("approve once") ||
                n == "run" || n == "continue" || n == "proceed" ||
                name == "允许" || name.StartsWith("仅允许一次") || name.StartsWith("允许本次") ||
                name == "批准" || name == "运行" || name == "继续" || name == "确认";
        }

        private static bool IsActionableCandidate(AutomationElement element)
        {
            try
            {
                if (element.Current.ControlType == ControlType.Button) return true;
                object pattern;
                return element.TryGetCurrentPattern(InvokePattern.Pattern, out pattern);
            }
            catch { return false; }
        }

        private static bool IsPersistentButton(string name)
        {
            return Regex.IsMatch(name, "always|session|始终|本次会话", RegexOptions.IgnoreCase);
        }

        private static string Matches(string text, Regex[] patterns)
        {
            if (String.IsNullOrEmpty(text)) return null;
            foreach (Regex regex in patterns)
                try { if (regex.IsMatch(text)) return regex.ToString(); } catch (RegexMatchTimeoutException) { }
            return null;
        }

        private static string Hash(string value)
        {
            using (SHA256 sha = SHA256.Create())
                return BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(value)))
                    .Replace("-", "").Substring(0, 16);
        }

        private void Save(AuthorizationRecord record)
        {
            try { store.Append(record); }
            catch (Exception ex) { record.Error = I18n.T("日志写入失败：", "Audit write failed: ") + OneLine(ex.Message, 300); }
            Action<AuthorizationRecord> handler = RecordCreated;
            if (handler != null) handler(record);
        }

        private void SendStatus(string status)
        {
            Action<string> handler = StatusChanged;
            if (handler != null) handler(status);
        }

        internal static string OneLine(string value, int max)
        {
            if (value == null) return "";
            value = Regex.Replace(Regex.Replace(value, @"[\r\n\t]+", " "), @"\s{2,}", " ").Trim();
            return value.Length <= max ? value : value.Substring(0, max) + "...";
        }

        public void Dispose() { Stop(); }
    }

    internal sealed class MainForm : Form
    {
        private readonly AuditStore store = new AuditStore();
        private readonly KiroWatcher watcher;
        private readonly DataGridView grid = new DataGridView();
        private readonly Label status = new Label();
        private readonly Button toggle = new Button();
        private readonly CheckBox authorizeAll = new CheckBox();
        private readonly CheckBox protect = new CheckBox();
        private readonly CheckBox startup = new CheckBox();
        private readonly ComboBox resultFilter = new ComboBox();
        private readonly TextBox search = new TextBox();
        private readonly NotifyIcon tray = new NotifyIcon();
        private bool allowExit;
        private bool suppressStartupChange;

        public MainForm()
        {
            watcher = new KiroWatcher(store);
            Text = I18n.T("Kiro AI 自动授权", "Kiro AI Auto Approve");
            Icon = SystemIcons.Shield;
            Width = 1080;
            Height = 650;
            MinimumSize = new Size(840, 500);
            StartPosition = FormStartPosition.CenterScreen;

            TableLayoutPanel layout = new TableLayoutPanel();
            layout.Dock = DockStyle.Fill;
            layout.ColumnCount = 1;
            layout.RowCount = 3;
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 165));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 46));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            Controls.Add(layout);

            Panel header = new Panel(); header.Dock = DockStyle.Fill; layout.Controls.Add(header, 0, 0);
            Label title = new Label();
            title.Text = I18n.T("Kiro AI 自动授权", "Kiro AI Auto Approve"); title.Font = new Font(Font.FontFamily, 16, FontStyle.Bold);
            title.AutoSize = true; title.Location = new Point(14, 12); header.Controls.Add(title);
            status.AutoSize = true; status.ForeColor = Color.DarkGreen; status.Location = new Point(17, 48); header.Controls.Add(status);
            toggle.Text = I18n.T("暂停监听", "Pause"); toggle.Size = new Size(100, 32); toggle.Location = new Point(14, 76);
            toggle.Click += delegate { Toggle(); }; header.Controls.Add(toggle);
            authorizeAll.Text = I18n.T("完整授权（自动允许所有 Kiro AI 请求）",
                "Full authorization (automatically allow all Kiro AI requests)"); authorizeAll.Checked = true;
            authorizeAll.AutoSize = true; authorizeAll.Location = new Point(132, 83);
            authorizeAll.CheckedChanged += delegate { watcher.AuthorizeAll = authorizeAll.Checked; }; header.Controls.Add(authorizeAll);
            protect.Text = I18n.T("拦截删库、递归删除等高风险命令",
                "Block high-risk commands such as database drops and recursive deletion"); protect.AutoSize = true;
            protect.Location = new Point(132, 109); protect.CheckedChanged += delegate { watcher.ProtectHighRisk = protect.Checked; }; header.Controls.Add(protect);
            startup.Text = I18n.T("开机自动启动", "Start with Windows"); startup.AutoSize = true; startup.Location = new Point(700, 109);
            startup.Checked = StartupEnabled(); startup.CheckedChanged += delegate { if (!suppressStartupChange) SetStartup(startup.Checked); };
            header.Controls.Add(startup);
            Label warning = new Label(); warning.AutoSize = true; warning.ForeColor = Color.DarkOrange;
            warning.Text = I18n.T(
                "完整授权允许 Kiro 执行其请求的命令。关闭主窗口后程序仍在托盘监听；如需保护可勾选高风险拦截。",
                "Full authorization allows Kiro to run requested commands. Closing this window keeps the tray watcher active; enable protection if needed.");
            warning.Location = new Point(17, 138); header.Controls.Add(warning);

            Panel filters = new Panel(); filters.Dock = DockStyle.Fill; layout.Controls.Add(filters, 0, 1);
            Label history = new Label(); history.Text = I18n.T("授权记录", "Authorization history"); history.Font = new Font(Font, FontStyle.Bold);
            history.AutoSize = true; history.Location = new Point(14, 15); filters.Controls.Add(history);
            resultFilter.DropDownStyle = ComboBoxStyle.DropDownList;
            resultFilter.Items.AddRange(new object[] { I18n.T("全部结果", "All results"), "approved", "blocked", "error", "unmatched", "unresolved", "skipped" });
            resultFilter.SelectedIndex = 0; resultFilter.Location = new Point(92, 11); resultFilter.Width = 120;
            resultFilter.SelectedIndexChanged += delegate { RefreshHistory(); }; filters.Controls.Add(resultFilter);
            search.Location = new Point(225, 11); search.Width = 300; search.TextChanged += delegate { RefreshHistory(); }; filters.Controls.Add(search);
            Label hint = new Label(); hint.Text = I18n.T("搜索命令/窗口", "Search command/window"); hint.ForeColor = Color.Gray;
            hint.AutoSize = true; hint.Location = new Point(532, 15); filters.Controls.Add(hint);
            Button openLog = new Button(); openLog.Text = I18n.T("打开日志目录", "Open log folder"); openLog.AutoSize = true; openLog.Location = new Point(700, 8);
            openLog.Click += delegate { Process.Start("explorer.exe", "/select,\"" + store.LogPath + "\""); }; filters.Controls.Add(openLog);
            Button refresh = new Button(); refresh.Text = I18n.T("刷新", "Refresh"); refresh.AutoSize = true; refresh.Location = new Point(815, 8);
            refresh.Click += delegate { RefreshHistory(); }; filters.Controls.Add(refresh);

            grid.Dock = DockStyle.Fill; grid.ReadOnly = true; grid.AllowUserToAddRows = false;
            grid.AllowUserToDeleteRows = false; grid.RowHeadersVisible = false; grid.BackgroundColor = SystemColors.Window;
            grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect; grid.AutoSizeRowsMode = DataGridViewAutoSizeRowsMode.DisplayedCells;
            grid.Columns.Add("Time", I18n.T("时间", "Time")); grid.Columns.Add("Decision", I18n.T("结果", "Result"));
            grid.Columns.Add("Reason", I18n.T("原因", "Reason"));
            grid.Columns.Add("Window", I18n.T("Kiro 窗口", "Kiro window")); grid.Columns.Add("Prompt", I18n.T("授权内容", "Authorization request"));
            grid.Columns[0].Width = 145; grid.Columns[1].Width = 75; grid.Columns[2].Width = 145; grid.Columns[3].Width = 170;
            grid.Columns[4].AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill; layout.Controls.Add(grid, 0, 2);

            ContextMenuStrip menu = new ContextMenuStrip();
            menu.Items.Add(I18n.T("打开", "Open"), null, delegate { RestoreWindow(); });
            menu.Items.Add(I18n.T("暂停/继续", "Pause/Resume"), null, delegate { Toggle(); });
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add(I18n.T("退出程序", "Exit"), null, delegate { ExitProgram(); });
            tray.Icon = SystemIcons.Shield; tray.Text = I18n.T("Kiro AI 自动授权", "Kiro AI Auto Approve"); tray.Visible = true; tray.ContextMenuStrip = menu;
            tray.DoubleClick += delegate { RestoreWindow(); };

            watcher.RecordCreated += delegate { if (!IsDisposed) try { BeginInvoke(new Action(RefreshHistory)); } catch { } };
            watcher.StatusChanged += delegate(string text)
            {
                if (!IsDisposed) try { BeginInvoke(new Action(delegate { status.Text = "● " + text; status.ForeColor = watcher.IsRunning ? Color.DarkGreen : Color.Gray; })); } catch { }
            };
            FormClosing += OnClosing;
            Resize += delegate { if (WindowState == FormWindowState.Minimized) Hide(); };
            Shown += delegate { watcher.Start(); RefreshHistory(); };
        }

        private void Toggle()
        {
            if (watcher.IsRunning) { watcher.Stop(); toggle.Text = I18n.T("开始监听", "Start watching"); }
            else { watcher.Start(); toggle.Text = I18n.T("暂停监听", "Pause"); }
        }

        private void RefreshHistory()
        {
            string filter = resultFilter.SelectedIndex <= 0 ? "" : resultFilter.SelectedItem.ToString();
            string query = search.Text.Trim();
            grid.Rows.Clear();
            foreach (AuthorizationRecord record in store.ReadAll().Take(1000))
            {
                if (filter.Length > 0 && !String.Equals(record.Decision, filter, StringComparison.OrdinalIgnoreCase)) continue;
                string combined = record.Prompt + " " + record.WindowTitle + " " + record.Reason;
                if (query.Length > 0 && combined.IndexOf(query, StringComparison.OrdinalIgnoreCase) < 0) continue;
                string time = record.Timestamp; DateTimeOffset parsed;
                if (DateTimeOffset.TryParse(time, out parsed)) time = parsed.LocalDateTime.ToString("yyyy-MM-dd HH:mm:ss");
                grid.Rows.Add(time, record.Decision, record.Reason, record.WindowTitle, record.Prompt);
            }
        }

        private bool StartupEnabled()
        {
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run"))
                return key != null && key.GetValue("KiroAutoApprove") != null;
        }

        private void SetStartup(bool enabled)
        {
            try
            {
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run"))
                {
                    if (enabled) key.SetValue("KiroAutoApprove", "\"" + Application.ExecutablePath + "\"");
                    else key.DeleteValue("KiroAutoApprove", false);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(I18n.T("开机启动设置失败：", "Failed to configure startup: ") + ex.Message,
                    I18n.T("Kiro 自动授权", "Kiro Auto Approve"), MessageBoxButtons.OK, MessageBoxIcon.Warning);
                suppressStartupChange = true; startup.Checked = !enabled; suppressStartupChange = false;
            }
        }

        private void OnClosing(object sender, FormClosingEventArgs e)
        {
            if (!allowExit && e.CloseReason == CloseReason.UserClosing)
            {
                e.Cancel = true; Hide();
                tray.ShowBalloonTip(1500, I18n.T("Kiro 自动授权", "Kiro Auto Approve"),
                    I18n.T("程序仍在后台监听，双击托盘图标可打开。",
                        "The watcher is still running in the background. Double-click the tray icon to reopen."), ToolTipIcon.Info);
            }
        }

        private void RestoreWindow() { Show(); WindowState = FormWindowState.Normal; Activate(); }
        private void ExitProgram() { allowExit = true; watcher.Dispose(); tray.Visible = false; Close(); }

        protected override void Dispose(bool disposing)
        {
            if (disposing) { watcher.Dispose(); tray.Dispose(); }
            base.Dispose(disposing);
        }
    }
}
