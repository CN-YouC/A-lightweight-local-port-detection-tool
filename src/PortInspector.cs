using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Management;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;

[assembly: System.Reflection.AssemblyTitle("端口检测工具")]
[assembly: System.Reflection.AssemblyDescription("查看本机被占用端口、占用它的文件与所在文件夹，并查找空闲端口")]
[assembly: System.Reflection.AssemblyProduct("端口检测工具")]
[assembly: System.Reflection.AssemblyVersion("1.0.0.0")]
[assembly: System.Reflection.AssemblyFileVersion("1.0.0.0")]

namespace PortInspector
{
    // ---------------------------------------------------------------- 数据模型

    public class PortRow
    {
        public int Port { get; set; }
        public string Proto { get; set; }
        public string Address { get; set; }
        public string State { get; set; }
        public int Pid { get; set; }
        public string ProcessName { get; set; }
        public string ExePath { get; set; }
        public string RunTarget { get; set; }
        public string CommandLine { get; set; }

        public string OwnerFile
        {
            get { return string.IsNullOrEmpty(RunTarget) ? ExePath : RunTarget; }
        }

        public string OwnerFolder
        {
            get
            {
                string f = OwnerFile;
                if (string.IsNullOrEmpty(f)) return "";
                try
                {
                    string dir = Path.GetDirectoryName(f);
                    return string.IsNullOrEmpty(dir) ? "" : dir;
                }
                catch { return ""; }
            }
        }
    }

    public class ProcInfo
    {
        public string Name;
        public string ExePath;
        public string CommandLine;
    }

    public class FreeScanResult
    {
        public List<int> Free = new List<int>();
        public List<int> Reserved = new List<int>();
        public List<int> Occupied = new List<int>();
        public int Total;
    }

    // ---------------------------------------------------------------- 采集逻辑

    public static class NativeApi
    {
        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint access, bool inheritHandle, int processId);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
        private static extern bool QueryFullProcessImageName(IntPtr hProcess, uint flags, StringBuilder exeName, ref int size);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        public static string GetProcessPath(int pid)
        {
            if (pid <= 0) return null;
            IntPtr h = IntPtr.Zero;
            try
            {
                h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                if (h == IntPtr.Zero) return null;
                StringBuilder sb = new StringBuilder(1024);
                int size = sb.Capacity;
                if (QueryFullProcessImageName(h, 0, sb, ref size)) return sb.ToString(0, size);
                return null;
            }
            catch { return null; }
            finally
            {
                if (h != IntPtr.Zero) { try { CloseHandle(h); } catch { } }
            }
        }
    }

    public static class NetScanner
    {
        public static string RunNetstat()
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("netstat.exe", "-ano");
                psi.UseShellExecute = false;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                psi.CreateNoWindow = true;
                psi.StandardOutputEncoding = Encoding.Default;
                using (Process p = Process.Start(psi))
                {
                    string output = p.StandardOutput.ReadToEnd();
                    p.WaitForExit(15000);
                    return output;
                }
            }
            catch { return null; }
        }

        public static Dictionary<int, ProcInfo> LoadProcesses()
        {
            Dictionary<int, ProcInfo> map = new Dictionary<int, ProcInfo>();
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                    "SELECT ProcessId,Name,ExecutablePath,CommandLine FROM Win32_Process"))
                {
                    using (ManagementObjectCollection results = searcher.Get())
                    {
                        foreach (ManagementObject mo in results)
                        {
                            try
                            {
                                int pid = Convert.ToInt32(mo["ProcessId"]);
                                ProcInfo info = new ProcInfo();
                                info.Name = Convert.ToString(mo["Name"]);
                                try { info.ExePath = Convert.ToString(mo["ExecutablePath"]); }
                                catch { info.ExePath = null; }
                                try { info.CommandLine = Convert.ToString(mo["CommandLine"]); }
                                catch { info.CommandLine = null; }
                                map[pid] = info;
                            }
                            catch { }
                            finally { mo.Dispose(); }
                        }
                    }
                }
            }
            catch { }

            if (map.Count == 0)
            {
                try
                {
                    foreach (Process p in Process.GetProcesses())
                    {
                        try
                        {
                            ProcInfo info = new ProcInfo();
                            info.Name = p.ProcessName + ".exe";
                            try { info.ExePath = p.MainModule.FileName; }
                            catch { info.ExePath = null; }
                            map[p.Id] = info;
                        }
                        catch { }
                        finally { p.Dispose(); }
                    }
                }
                catch { }
            }
            return map;
        }

        public static List<PortRow> CollectPorts(bool includeAll, out string error)
        {
            error = null;
            List<PortRow> rows = new List<PortRow>();
            string output = RunNetstat();
            if (output == null)
            {
                error = "无法运行 netstat.exe，端口列表读取失败。";
                return rows;
            }

            Dictionary<int, ProcInfo> procs = LoadProcesses();

            foreach (string raw in output.Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string line = raw.Trim();
                if (line.Length == 0) continue;
                bool isTcp = line.StartsWith("TCP", StringComparison.OrdinalIgnoreCase) && line.Length > 3 && char.IsWhiteSpace(line[3]);
                bool isUdp = line.StartsWith("UDP", StringComparison.OrdinalIgnoreCase) && line.Length > 3 && char.IsWhiteSpace(line[3]);
                if (!isTcp && !isUdp) continue;

                string[] parts = Regex.Split(line, "\\s+");
                if (isTcp && parts.Length < 5) continue;
                if (isUdp && parts.Length < 4) continue;

                string proto = isTcp ? "TCP" : "UDP";
                string local = parts[1];
                string state = isTcp ? parts[3] : "UDP";
                string pidText = isTcp ? parts[4] : parts[3];

                if (!includeAll && isTcp && !string.Equals(state, "LISTENING", StringComparison.OrdinalIgnoreCase))
                    continue;

                int idx = local.LastIndexOf(':');
                if (idx <= 0 || idx >= local.Length - 1) continue;
                string addr = local.Substring(0, idx);
                int port;
                if (!int.TryParse(local.Substring(idx + 1), out port)) continue;
                int pid;
                if (!int.TryParse(pidText, out pid)) pid = 0;

                PortRow row = new PortRow();
                row.Port = port;
                row.Proto = proto;
                row.Address = NormalizeAddress(addr);
                row.State = state;
                row.Pid = pid;

                ProcInfo info;
                if (procs.TryGetValue(pid, out info))
                {
                    row.ProcessName = info.Name;
                    row.ExePath = info.ExePath;
                    row.CommandLine = info.CommandLine;
                    row.RunTarget = FindRunTarget(info.ExePath, info.CommandLine);
                }

                // WMI 拿不到路径时，用系统 API 直接查（普通权限也能查大多数进程）
                if (string.IsNullOrEmpty(row.ExePath))
                {
                    string nativePath = NativeApi.GetProcessPath(pid);
                    if (!string.IsNullOrEmpty(nativePath))
                    {
                        row.ExePath = nativePath;
                        if (string.IsNullOrEmpty(row.ProcessName)) row.ProcessName = Path.GetFileName(nativePath);
                    }
                }

                if (string.IsNullOrEmpty(row.ProcessName))
                {
                    try
                    {
                        Process p = Process.GetProcessById(pid);
                        row.ProcessName = p.ProcessName + ".exe";
                        try { row.ExePath = p.MainModule.FileName; }
                        catch { }
                        p.Dispose();
                    }
                    catch { }
                }
                rows.Add(row);
            }

            rows.Sort(delegate (PortRow a, PortRow b)
            {
                int c = a.Port.CompareTo(b.Port);
                if (c != 0) return c;
                return string.CompareOrdinal(a.Proto, b.Proto);
            });
            return rows;
        }

        private static string NormalizeAddress(string addr)
        {
            if (addr.Length >= 2 && addr[0] == '[' && addr[addr.Length - 1] == ']')
                return addr.Substring(1, addr.Length - 2);
            return addr;
        }

        // 命令行里找“真正被运行的文件”，例如 python.exe bot.py 里的 bot.py
        public static string FindRunTarget(string exePath, string cmdLine)
        {
            if (string.IsNullOrEmpty(cmdLine)) return null;
            string exeName = "";
            try { exeName = Path.GetFileName(exePath); } catch { }
            if (string.IsNullOrEmpty(exeName)) return null;
            exeName = exeName.ToLowerInvariant();

            bool scriptHost = exeName == "python.exe" || exeName == "pythonw.exe" || exeName == "py.exe"
                || exeName == "node.exe" || exeName == "java.exe" || exeName == "javaw.exe"
                || exeName == "dotnet.exe" || exeName == "cmd.exe" || exeName == "powershell.exe"
                || exeName == "pwsh.exe" || exeName == "wscript.exe" || exeName == "cscript.exe";
            if (!scriptHost) return null;

            List<string> tokens = SplitCommandLine(cmdLine);

            // 找带脚本扩展名的参数
            for (int i = 1; i < tokens.Count; i++)
            {
                string t = tokens[i];
                if (t.Length == 0) continue;
                if (t[0] == '-' || t[0] == '/') continue;
                string ext = "";
                try { ext = Path.GetExtension(t).ToLowerInvariant(); } catch { }
                if (ext == ".py" || ext == ".pyw" || ext == ".js" || ext == ".mjs" || ext == ".cjs"
                    || ext == ".jar" || ext == ".ps1" || ext == ".bat" || ext == ".cmd" || ext == ".vbs"
                    || ext == ".exe" || ext == ".dll")
                {
                    return t;
                }
            }
            return null;
        }

        public static List<string> SplitCommandLine(string s)
        {
            List<string> list = new List<string>();
            StringBuilder sb = new StringBuilder();
            bool inQuotes = false;
            foreach (char c in s)
            {
                if (c == '"') { inQuotes = !inQuotes; continue; }
                if (!inQuotes && (c == ' ' || c == '\t'))
                {
                    if (sb.Length > 0) { list.Add(sb.ToString()); sb.Length = 0; }
                    continue;
                }
                sb.Append(c);
            }
            if (sb.Length > 0) list.Add(sb.ToString());
            return list;
        }

        public static FreeScanResult FindFreePorts(int from, int to, BackgroundWorker worker)
        {
            FreeScanResult result = new FreeScanResult();
            result.Total = to - from + 1;
            int counter = 0;
            for (int port = from; port <= to; port++)
            {
                counter++;
                if (worker != null && worker.WorkerReportsProgress && counter % 25 == 0)
                {
                    int pct = (int)((long)counter * 100 / result.Total);
                    worker.ReportProgress(pct);
                    if (worker.CancellationPending) break;
                }

                string reason;
                if (!IsTcpBindable(port, out reason))
                {
                    if (reason == "系统保留") result.Reserved.Add(port);
                    else result.Occupied.Add(port);
                    continue;
                }
                if (!IsUdpBindable(port, out reason))
                {
                    if (reason == "系统保留") result.Reserved.Add(port);
                    else result.Occupied.Add(port);
                    continue;
                }
                result.Free.Add(port);
            }
            return result;
        }

        private static bool IsTcpBindable(int port, out string reason)
        {
            reason = "";
            TcpListener listener = null;
            try
            {
                listener = new TcpListener(IPAddress.Any, port);
                listener.ExclusiveAddressUse = true;
                listener.Start();
            }
            catch (SocketException ex)
            {
                reason = ex.SocketErrorCode == SocketError.AccessDenied ? "系统保留" : "占用";
                return false;
            }
            catch
            {
                reason = "检测失败";
                return false;
            }
            finally
            {
                if (listener != null)
                {
                    try { listener.Stop(); } catch { }
                }
            }

            // IPv6 单独占用时也算不可用
            if (Socket.OSSupportsIPv6)
            {
                TcpListener v6 = null;
                try
                {
                    v6 = new TcpListener(IPAddress.IPv6Any, port);
                    v6.ExclusiveAddressUse = true;
                    v6.Start();
                }
                catch (SocketException ex)
                {
                    if (ex.SocketErrorCode != SocketError.AddressFamilyNotSupported
                        && ex.SocketErrorCode != SocketError.ProtocolNotSupported)
                    {
                        reason = ex.SocketErrorCode == SocketError.AccessDenied ? "系统保留" : "IPv6占用";
                        return false;
                    }
                }
                catch { }
                finally
                {
                    if (v6 != null) { try { v6.Stop(); } catch { } }
                }
            }
            return true;
        }

        private static bool IsUdpBindable(int port, out string reason)
        {
            reason = "";
            Socket s = null;
            try
            {
                s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                s.ExclusiveAddressUse = true;
                s.Bind(new IPEndPoint(IPAddress.Any, port));
                return true;
            }
            catch (SocketException ex)
            {
                reason = ex.SocketErrorCode == SocketError.AccessDenied ? "系统保留" : "UDP占用";
                return false;
            }
            catch
            {
                reason = "检测失败";
                return false;
            }
            finally
            {
                if (s != null) { try { s.Close(); } catch { } }
            }
        }
    }

    // ---------------------------------------------------------------- 主窗口

    public class MainForm : Form
    {
        private DataGridView _gridPorts;
        private DataGridView _gridFree;
        private TextBox _txtSearch;
        private CheckBox _chkAll;
        private NumericUpDown _numFrom;
        private NumericUpDown _numTo;
        private Button _btnRefresh;
        private Button _btnScan;
        private Button _btnExport;
        private Button _btnAdmin;
        private ToolStripStatusLabel _lblPerm;
        private ToolStripStatusLabel _lblStat;
        private ToolStripStatusLabel _lblMsg;
        private Label _lblFreeInfo;

        private BackgroundWorker _portsWorker;
        private BackgroundWorker _freeWorker;

        private List<PortRow> _allRows = new List<PortRow>();
        private List<PortRow> _viewRows = new List<PortRow>();
        private string _sortColumn = "port";
        private SortOrder _sortOrder = SortOrder.Ascending;
        private bool _isAdmin;
        private bool _busy;

        private bool _autoRefresh = true;

        public MainForm() : this(true) { }

        public MainForm(bool autoRefresh)
        {
            _autoRefresh = autoRefresh;
            BuildUi();
            CheckAdmin();
            _portsWorker = new BackgroundWorker();
            _portsWorker.DoWork += PortsWorker_DoWork;
            _portsWorker.RunWorkerCompleted += PortsWorker_Completed;

            _freeWorker = new BackgroundWorker();
            _freeWorker.WorkerReportsProgress = true;
            _freeWorker.WorkerSupportsCancellation = true;
            _freeWorker.DoWork += FreeWorker_DoWork;
            _freeWorker.ProgressChanged += FreeWorker_Progress;
            _freeWorker.RunWorkerCompleted += FreeWorker_Completed;

            this.Shown += delegate
            {
                if (_autoRefresh) RefreshPorts();
            };
        }

        // ------------------------------------------------------------ 界面搭建

        private void BuildUi()
        {
            this.Text = "端口检测工具  v1.0";
            this.StartPosition = FormStartPosition.CenterScreen;
            this.Size = new Size(1280, 840);
            this.MinimumSize = new Size(980, 620);
            this.Font = new Font("微软雅黑", 9F);
            this.BackColor = Color.White;

            FlowLayoutPanel toolbar = new FlowLayoutPanel();
            toolbar.Dock = DockStyle.Top;
            toolbar.Height = 46;
            toolbar.Padding = new Padding(8, 7, 8, 4);
            toolbar.WrapContents = false;
            toolbar.BackColor = Color.FromArgb(246, 247, 249);

            _btnRefresh = MakeButton("重新检测", 96);
            _btnRefresh.Click += delegate { RefreshPorts(); };

            Label lblRange = MakeLabel("空闲端口范围");
            lblRange.Margin = new Padding(14, 8, 4, 0);

            _numFrom = MakeNumber(8000, 70);
            Label lblTo = MakeLabel("至");
            lblTo.Margin = new Padding(4, 8, 4, 0);
            _numTo = MakeNumber(8100, 70);

            _btnScan = MakeButton("查找空闲端口", 116);
            _btnScan.Click += delegate { ScanFreePorts(); };

            Label sep = MakeLabel("│");
            sep.ForeColor = Color.Silver;
            sep.Margin = new Padding(12, 8, 12, 0);

            Label lblSearch = MakeLabel("搜索");
            lblSearch.Margin = new Padding(0, 8, 4, 0);
            _txtSearch = new TextBox();
            _txtSearch.Width = 170;
            _txtSearch.Margin = new Padding(0, 5, 0, 0);
            _txtSearch.TextChanged += delegate { ApplyFilter(); };

            _chkAll = new CheckBox();
            _chkAll.Text = "显示全部连接";
            _chkAll.AutoSize = true;
            _chkAll.Margin = new Padding(12, 8, 0, 0);
            _chkAll.CheckedChanged += delegate { RefreshPorts(); };

            _btnExport = MakeButton("导出 CSV", 90);
            _btnExport.Click += delegate { ExportCsv(); };

            _btnAdmin = MakeButton("以管理员身份重启", 140);
            _btnAdmin.Click += delegate { RestartAsAdmin(); };

            toolbar.Controls.Add(_btnRefresh);
            toolbar.Controls.Add(lblRange);
            toolbar.Controls.Add(_numFrom);
            toolbar.Controls.Add(lblTo);
            toolbar.Controls.Add(_numTo);
            toolbar.Controls.Add(_btnScan);
            toolbar.Controls.Add(sep);
            toolbar.Controls.Add(lblSearch);
            toolbar.Controls.Add(_txtSearch);
            toolbar.Controls.Add(_chkAll);
            toolbar.Controls.Add(_btnExport);
            toolbar.Controls.Add(_btnAdmin);

            SplitContainer split = new SplitContainer();
            split.Dock = DockStyle.Fill;
            split.Orientation = Orientation.Horizontal;
            split.SplitterWidth = 6;
            split.BackColor = Color.FromArgb(230, 232, 236);

            // 上半：占用端口
            Panel p1 = new Panel();
            p1.Dock = DockStyle.Fill;
            p1.Padding = new Padding(8, 6, 8, 0);

            Label t1 = new Label();
            t1.Text = "被占用的端口（TCP 监听 / UDP 绑定）";
            t1.Dock = DockStyle.Top;
            t1.Height = 26;
            t1.Font = new Font("微软雅黑", 10F, FontStyle.Bold);
            t1.ForeColor = Color.FromArgb(32, 32, 32);

            _gridPorts = new DataGridView();
            _gridPorts.Dock = DockStyle.Fill;
            _gridPorts.AutoGenerateColumns = false;
            _gridPorts.ReadOnly = true;
            _gridPorts.AllowUserToAddRows = false;
            _gridPorts.AllowUserToDeleteRows = false;
            _gridPorts.AllowUserToResizeRows = false;
            _gridPorts.RowHeadersVisible = false;
            _gridPorts.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
            _gridPorts.MultiSelect = false;
            _gridPorts.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
            _gridPorts.BackgroundColor = Color.White;
            _gridPorts.BorderStyle = BorderStyle.FixedSingle;
            _gridPorts.EnableHeadersVisualStyles = false;
            _gridPorts.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(240, 242, 245);
            _gridPorts.ColumnHeadersDefaultCellStyle.Font = new Font("微软雅黑", 9F, FontStyle.Bold);
            _gridPorts.ColumnHeadersHeight = 30;
            _gridPorts.RowTemplate.Height = 24;
            _gridPorts.AlternatingRowsDefaultCellStyle.BackColor = Color.FromArgb(250, 250, 252);
            _gridPorts.GridColor = Color.FromArgb(232, 234, 238);
            _gridPorts.CellFormatting += GridPorts_CellFormatting;
            _gridPorts.CellToolTipTextNeeded += GridPorts_CellToolTip;
            _gridPorts.CellDoubleClick += GridPorts_CellDoubleClick;
            _gridPorts.ColumnHeaderMouseClick += GridPorts_ColumnHeaderMouseClick;

            AddColumn(_gridPorts, "port", "端口", "Port", 50, 50);
            AddColumn(_gridPorts, "proto", "协议", "Proto", 45, 45);
            AddColumn(_gridPorts, "addr", "本地地址", "Address", 110, 80);
            AddColumn(_gridPorts, "state", "状态", "State", 80, 70);
            AddColumn(_gridPorts, "pid", "PID", "Pid", 50, 50);
            AddColumn(_gridPorts, "proc", "进程名", "ProcessName", 100, 80);
            AddColumn(_gridPorts, "file", "占用文件（完整路径）", "OwnerFile", 230, 160);
            AddColumn(_gridPorts, "folder", "所在文件夹", "OwnerFolder", 170, 120);
            AddColumn(_gridPorts, "cmd", "命令行", "CommandLine", 160, 100);

            ContextMenuStrip menu = new ContextMenuStrip();
            menu.Items.Add("复制整行", null, delegate { CopySelectedRow(); });
            menu.Items.Add("复制占用文件路径", null, delegate { CopySelectedPath(); });
            menu.Items.Add("打开文件所在文件夹", null, delegate { OpenSelectedFolder(); });
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("结束该进程", null, delegate { KillSelectedProcess(); });
            _gridPorts.ContextMenuStrip = menu;

            p1.Controls.Add(_gridPorts);
            p1.Controls.Add(t1);

            // 下半：空闲端口
            Panel p2 = new Panel();
            p2.Dock = DockStyle.Fill;
            p2.Padding = new Padding(8, 6, 8, 6);

            _lblFreeInfo = new Label();
            _lblFreeInfo.Text = "空闲端口（设置范围后点“查找空闲端口”）";
            _lblFreeInfo.Dock = DockStyle.Top;
            _lblFreeInfo.Height = 26;
            _lblFreeInfo.Font = new Font("微软雅黑", 10F, FontStyle.Bold);
            _lblFreeInfo.ForeColor = Color.FromArgb(32, 32, 32);

            _gridFree = new DataGridView();
            _gridFree.Dock = DockStyle.Fill;
            _gridFree.ReadOnly = true;
            _gridFree.AllowUserToAddRows = false;
            _gridFree.AllowUserToDeleteRows = false;
            _gridFree.AllowUserToResizeRows = false;
            _gridFree.RowHeadersVisible = false;
            _gridFree.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
            _gridFree.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
            _gridFree.BackgroundColor = Color.White;
            _gridFree.BorderStyle = BorderStyle.FixedSingle;
            _gridFree.EnableHeadersVisualStyles = false;
            _gridFree.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(240, 242, 245);
            _gridFree.ColumnHeadersDefaultCellStyle.Font = new Font("微软雅黑", 9F, FontStyle.Bold);
            _gridFree.ColumnHeadersHeight = 30;
            _gridFree.RowTemplate.Height = 24;
            _gridFree.AlternatingRowsDefaultCellStyle.BackColor = Color.FromArgb(250, 250, 252);
            _gridFree.GridColor = Color.FromArgb(232, 234, 238);

            DataGridViewTextBoxColumn cPort = new DataGridViewTextBoxColumn();
            cPort.Name = "fport"; cPort.HeaderText = "空闲端口"; cPort.FillWeight = 25; cPort.MinimumWidth = 100;
            cPort.SortMode = DataGridViewColumnSortMode.Automatic; cPort.ReadOnly = true;
            DataGridViewTextBoxColumn cNote = new DataGridViewTextBoxColumn();
            cNote.Name = "fnote"; cNote.HeaderText = "说明"; cNote.FillWeight = 75; cNote.MinimumWidth = 200;
            cNote.SortMode = DataGridViewColumnSortMode.NotSortable; cNote.ReadOnly = true;
            _gridFree.Columns.Add(cPort);
            _gridFree.Columns.Add(cNote);

            ContextMenuStrip freeMenu = new ContextMenuStrip();
            freeMenu.Items.Add("复制选中端口", null, delegate
            {
                if (_gridFree.CurrentRow != null)
                {
                    try { Clipboard.SetText(Convert.ToString(_gridFree.CurrentRow.Cells[0].Value)); } catch { }
                }
            });
            _gridFree.ContextMenuStrip = freeMenu;

            p2.Controls.Add(_gridFree);
            p2.Controls.Add(_lblFreeInfo);

            split.Panel1.Controls.Add(p1);
            split.Panel2.Controls.Add(p2);

            StatusStrip status = new StatusStrip();
            status.SizingGrip = false;
            _lblPerm = new ToolStripStatusLabel("权限：普通用户");
            _lblStat = new ToolStripStatusLabel("占用 0 项");
            _lblMsg = new ToolStripStatusLabel("就绪");
            _lblMsg.Spring = true;
            _lblMsg.TextAlign = ContentAlignment.MiddleLeft;
            status.Items.Add(_lblPerm);
            status.Items.Add(new ToolStripSeparator());
            status.Items.Add(_lblStat);
            status.Items.Add(new ToolStripSeparator());
            status.Items.Add(_lblMsg);

            this.Controls.Add(split);
            this.Controls.Add(status);
            this.Controls.Add(toolbar);
        }

        private static Button MakeButton(string text, int width)
        {
            Button b = new Button();
            b.Text = text;
            b.Width = width;
            b.Height = 30;
            b.Margin = new Padding(0, 0, 6, 0);
            b.FlatStyle = FlatStyle.System;
            b.UseVisualStyleBackColor = true;
            return b;
        }

        private static Label MakeLabel(string text)
        {
            Label l = new Label();
            l.Text = text;
            l.AutoSize = true;
            return l;
        }

        private static NumericUpDown MakeNumber(int value, int width)
        {
            NumericUpDown n = new NumericUpDown();
            n.Minimum = 1;
            n.Maximum = 65535;
            n.Value = value;
            n.Width = width;
            n.Margin = new Padding(0, 5, 0, 0);
            return n;
        }

        private static void AddColumn(DataGridView grid, string name, string header, string prop, int weight, int minWidth)
        {
            DataGridViewTextBoxColumn c = new DataGridViewTextBoxColumn();
            c.Name = name;
            c.HeaderText = header;
            c.DataPropertyName = prop;
            c.FillWeight = weight;
            c.MinimumWidth = minWidth;
            c.SortMode = DataGridViewColumnSortMode.Programmatic;
            c.ReadOnly = true;
            grid.Columns.Add(c);
        }

        // ------------------------------------------------------------ 检测

        private void CheckAdmin()
        {
            try
            {
                using (System.Security.Principal.WindowsIdentity id = System.Security.Principal.WindowsIdentity.GetCurrent())
                {
                    System.Security.Principal.WindowsPrincipal p = new System.Security.Principal.WindowsPrincipal(id);
                    _isAdmin = p.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
                }
            }
            catch { _isAdmin = false; }

            _lblPerm.Text = _isAdmin ? "权限：管理员（可读取全部进程路径）" : "权限：普通用户（部分系统进程读不到路径）";
            _lblPerm.ForeColor = _isAdmin ? Color.FromArgb(0, 128, 60) : Color.FromArgb(190, 90, 0);
        }

        private void RefreshPorts()
        {
            if (_busy) return;
            SetBusy(true, "正在检测本机端口…");
            _portsWorker.RunWorkerAsync(_chkAll.Checked);
        }

        private void PortsWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            bool includeAll = (bool)e.Argument;
            string error;
            List<PortRow> rows = NetScanner.CollectPorts(includeAll, out error);
            e.Result = new object[] { rows, error };
        }

        private void PortsWorker_Completed(object sender, RunWorkerCompletedEventArgs e)
        {
            try
            {
                object[] result = (object[])e.Result;
                _allRows = (List<PortRow>)result[0];
                string error = (string)result[1];
                ApplyFilter();
                if (!string.IsNullOrEmpty(error)) MessageBox.Show(this, error, "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                _lblMsg.Text = "检测完成，共 " + _allRows.Count + " 项";
            }
            catch (Exception ex)
            {
                _lblMsg.Text = "检测失败：" + ex.Message;
            }
            finally
            {
                SetBusy(false, null);
            }
        }

        private void ApplyFilter()
        {
            string key = _txtSearch.Text.Trim().ToLowerInvariant();
            _viewRows = new List<PortRow>();
            foreach (PortRow r in _allRows)
            {
                if (key.Length > 0)
                {
                    string blob = (r.Port.ToString() + " " + r.Proto + " " + r.Address + " " + r.State + " "
                        + r.Pid + " " + r.ProcessName + " " + r.ExePath + " " + r.RunTarget + " " + r.CommandLine).ToLowerInvariant();
                    if (blob.IndexOf(key) < 0) continue;
                }
                _viewRows.Add(r);
            }

            _gridPorts.DataSource = null;
            ApplySort();
            _lblStat.Text = "占用 " + _viewRows.Count + " 项" + (key.Length > 0 ? "（已筛选，共 " + _allRows.Count + "）" : "");
            if (!_isAdmin)
            {
                int missing = 0;
                foreach (PortRow r in _allRows) if (string.IsNullOrEmpty(r.OwnerFile)) missing++;
                if (missing > 0) _lblMsg.Text = "有 " + missing + " 个进程读不到文件路径，点右上角“以管理员身份重启”后再看";
            }
        }

        private void GridPorts_ColumnHeaderMouseClick(object sender, DataGridViewCellMouseEventArgs e)
        {
            string name = _gridPorts.Columns[e.ColumnIndex].Name;
            if (_sortColumn == name)
                _sortOrder = _sortOrder == SortOrder.Ascending ? SortOrder.Descending : SortOrder.Ascending;
            else
            {
                _sortColumn = name;
                _sortOrder = SortOrder.Ascending;
            }
            ApplySort();
        }

        private void ApplySort()
        {
            Comparison<PortRow> cmp = GetComparison(_sortColumn);
            _viewRows.Sort(cmp);
            if (_sortOrder == SortOrder.Descending) _viewRows.Reverse();

            foreach (DataGridViewColumn c in _gridPorts.Columns) c.HeaderCell.SortGlyphDirection = SortOrder.None;
            DataGridViewColumn col = _gridPorts.Columns[_sortColumn];
            if (col != null) col.HeaderCell.SortGlyphDirection = _sortOrder;

            // 排序后重新绑定，避免行与后台列表错位
            int index = _gridPorts.CurrentRow == null ? -1 : _gridPorts.CurrentRow.Index;
            _gridPorts.DataSource = null;
            _gridPorts.DataSource = new BindingList<PortRow>(_viewRows);
            if (index >= 0 && index < _viewRows.Count) _gridPorts.Rows[index].Selected = true;
        }

        private static Comparison<PortRow> GetComparison(string column)
        {
            switch (column)
            {
                case "port": return delegate(PortRow a, PortRow b) { return a.Port.CompareTo(b.Port); };
                case "pid": return delegate(PortRow a, PortRow b) { return a.Pid.CompareTo(b.Pid); };
                case "proto": return delegate(PortRow a, PortRow b) { return string.CompareOrdinal(a.Proto, b.Proto); };
                case "addr": return delegate(PortRow a, PortRow b) { return string.Compare(a.Address, b.Address, StringComparison.OrdinalIgnoreCase); };
                case "state": return delegate(PortRow a, PortRow b) { return string.Compare(a.State, b.State, StringComparison.OrdinalIgnoreCase); };
                case "proc": return delegate(PortRow a, PortRow b) { return string.Compare(a.ProcessName, b.ProcessName, StringComparison.OrdinalIgnoreCase); };
                case "file": return delegate(PortRow a, PortRow b) { return string.Compare(a.OwnerFile, b.OwnerFile, StringComparison.OrdinalIgnoreCase); };
                case "folder": return delegate(PortRow a, PortRow b) { return string.Compare(a.OwnerFolder, b.OwnerFolder, StringComparison.OrdinalIgnoreCase); };
                case "cmd": return delegate(PortRow a, PortRow b) { return string.Compare(a.CommandLine, b.CommandLine, StringComparison.OrdinalIgnoreCase); };
                default: return delegate(PortRow a, PortRow b) { return a.Port.CompareTo(b.Port); };
            }
        }

        private void GridPorts_CellFormatting(object sender, DataGridViewCellFormattingEventArgs e)
        {
            if (e.RowIndex < 0 || e.RowIndex >= _viewRows.Count) return;
            PortRow row = _viewRows[e.RowIndex];
            string name = _gridPorts.Columns[e.ColumnIndex].Name;

            if (name == "file")
            {
                if (string.IsNullOrEmpty(row.OwnerFile))
                {
                    e.Value = "（读取不到，需管理员权限）";
                    e.CellStyle.ForeColor = Color.Gray;
                    e.FormattingApplied = true;
                }
            }
            else if (name == "folder")
            {
                if (string.IsNullOrEmpty(row.OwnerFolder))
                {
                    e.Value = "";
                    e.FormattingApplied = true;
                }
            }
        }

        private void GridPorts_CellToolTip(object sender, DataGridViewCellToolTipTextNeededEventArgs e)
        {
            if (e.RowIndex < 0 || e.RowIndex >= _viewRows.Count) return;
            PortRow row = _viewRows[e.RowIndex];
            StringBuilder sb = new StringBuilder();
            sb.Append("PID：").Append(row.Pid).Append("\r\n");
            sb.Append("程序文件：").Append(string.IsNullOrEmpty(row.ExePath) ? "（读取不到）" : row.ExePath).Append("\r\n");
            if (!string.IsNullOrEmpty(row.RunTarget)) sb.Append("运行文件：").Append(row.RunTarget).Append("\r\n");
            sb.Append("命令行：").Append(string.IsNullOrEmpty(row.CommandLine) ? "（读取不到）" : row.CommandLine);
            e.ToolTipText = sb.ToString();
        }

        private void GridPorts_CellDoubleClick(object sender, DataGridViewCellEventArgs e)
        {
            if (e.RowIndex >= 0) OpenSelectedFolder();
        }

        // ------------------------------------------------------------ 空闲端口

        private void ScanFreePorts()
        {
            if (_busy) return;
            int from = (int)_numFrom.Value;
            int to = (int)_numTo.Value;
            if (from > to) { int t = from; from = to; to = t; }
            if (to - from + 1 > 8000)
            {
                if (MessageBox.Show(this, "范围较大（" + (to - from + 1) + " 个端口），可能需要几十秒，是否继续？",
                    "确认", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            }

            _gridFree.Rows.Clear();
            _lblFreeInfo.Text = "正在检测 " + from + " - " + to + " …";
            SetBusy(true, "正在查找空闲端口…");
            _freeWorker.RunWorkerAsync(new int[] { from, to });
        }

        private void FreeWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            int[] range = (int[])e.Argument;
            e.Result = NetScanner.FindFreePorts(range[0], range[1], (BackgroundWorker)sender);
        }

        private void FreeWorker_Progress(object sender, ProgressChangedEventArgs e)
        {
            _lblFreeInfo.Text = "正在检测… " + e.ProgressPercentage + "%";
        }

        private void FreeWorker_Completed(object sender, RunWorkerCompletedEventArgs e)
        {
            try
            {
                FillFreeGrid((FreeScanResult)e.Result);
            }
            catch (Exception ex)
            {
                _lblFreeInfo.Text = "查找失败：" + ex.Message;
            }
            finally
            {
                SetBusy(false, null);
            }
        }

        private void FillFreeGrid(FreeScanResult r)
        {
            _gridFree.SuspendLayout();
            _gridFree.Rows.Clear();
            foreach (int port in r.Free)
            {
                int i = _gridFree.Rows.Add(port, "TCP + UDP 均可绑定");
                if (i == 0)
                {
                    _gridFree.Rows[i].DefaultCellStyle.BackColor = Color.FromArgb(232, 246, 236);
                    _gridFree.Rows[i].Cells[1].Value = "TCP + UDP 均可绑定（推荐用这个）";
                }
            }
            if (r.Free.Count == 0)
            {
                _gridFree.Rows.Add("—", "该范围内没有空闲端口");
            }
            _gridFree.ResumeLayout();

            string info = "空闲端口 " + r.Free.Count + " 个";
            if (r.Reserved.Count > 0) info += "，系统保留 " + r.Reserved.Count + " 个";
            if (r.Occupied.Count > 0) info += "，被占用 " + r.Occupied.Count + " 个";
            _lblFreeInfo.Text = "空闲端口（" + _numFrom.Value + " - " + _numTo.Value + "）：" + info;
            _lblMsg.Text = r.Free.Count > 0 ? "推荐空闲端口：" + r.Free[0] : "该范围内没有空闲端口";
        }

        // 供截图模式使用：同步加载一次数据
        public void LoadDataSync()
        {
            string error;
            _allRows = NetScanner.CollectPorts(false, out error);
            ApplyFilter();
            FreeScanResult r = NetScanner.FindFreePorts((int)_numFrom.Value, (int)_numTo.Value, null);
            FillFreeGrid(r);
        }

        // ------------------------------------------------------------ 操作

        private PortRow SelectedRow()
        {
            if (_gridPorts.CurrentRow == null) return null;
            int i = _gridPorts.CurrentRow.Index;
            if (i < 0 || i >= _viewRows.Count) return null;
            return _viewRows[i];
        }

        private void CopySelectedRow()
        {
            PortRow r = SelectedRow();
            if (r == null) return;
            string text = r.Port + "\t" + r.Proto + "\t" + r.Address + "\t" + r.State + "\t" + r.Pid + "\t"
                + r.ProcessName + "\t" + r.OwnerFile + "\t" + r.OwnerFolder + "\t" + r.CommandLine;
            try { Clipboard.SetText(text); _lblMsg.Text = "已复制整行"; } catch { }
        }

        private void CopySelectedPath()
        {
            PortRow r = SelectedRow();
            if (r == null) return;
            try { Clipboard.SetText(r.OwnerFile ?? ""); _lblMsg.Text = "已复制文件路径"; } catch { }
        }

        private void OpenSelectedFolder()
        {
            PortRow r = SelectedRow();
            if (r == null) return;
            try
            {
                if (!string.IsNullOrEmpty(r.OwnerFile) && File.Exists(r.OwnerFile))
                {
                    Process.Start("explorer.exe", "/select,\"" + r.OwnerFile + "\"");
                    return;
                }
                if (!string.IsNullOrEmpty(r.OwnerFolder) && Directory.Exists(r.OwnerFolder))
                {
                    Process.Start("explorer.exe", "\"" + r.OwnerFolder + "\"");
                    return;
                }
            }
            catch { }
            MessageBox.Show(this, "读不到这个进程的文件位置。请用“以管理员身份重启”后再试。", "提示",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void KillSelectedProcess()
        {
            PortRow r = SelectedRow();
            if (r == null) return;
            if (r.Pid <= 4)
            {
                MessageBox.Show(this, "这是系统进程（PID " + r.Pid + "），不能结束。", "提示",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            string title = string.IsNullOrEmpty(r.ProcessName) ? ("PID " + r.Pid) : r.ProcessName;
            if (MessageBox.Show(this, "确定结束进程 " + title + "（PID " + r.Pid + "）吗？\r\n端口 " + r.Port + " 会随之释放。",
                "确认结束进程", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
            try
            {
                Process p = Process.GetProcessById(r.Pid);
                p.Kill();
                _lblMsg.Text = "已结束进程 " + title;
                RefreshPorts();
            }
            catch (ArgumentException)
            {
                _lblMsg.Text = "进程已经不存在了";
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "结束失败：" + ex.Message + "\r\n请用“以管理员身份重启”后再试。", "提示",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void ExportCsv()
        {
            if (_viewRows.Count == 0)
            {
                MessageBox.Show(this, "当前没有可导出的数据。", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            SaveFileDialog dlg = new SaveFileDialog();
            dlg.Filter = "CSV 文件 (*.csv)|*.csv|文本文件 (*.txt)|*.txt";
            dlg.FileName = "端口检测_" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + ".csv";
            if (dlg.ShowDialog(this) != DialogResult.OK) return;

            try
            {
                StringBuilder sb = new StringBuilder();
                sb.AppendLine("端口,协议,本地地址,状态,PID,进程名,占用文件,所在文件夹,命令行");
                foreach (PortRow r in _viewRows)
                {
                    sb.Append(r.Port).Append(',');
                    sb.Append(Csv(r.Proto)).Append(',');
                    sb.Append(Csv(r.Address)).Append(',');
                    sb.Append(Csv(r.State)).Append(',');
                    sb.Append(r.Pid).Append(',');
                    sb.Append(Csv(r.ProcessName)).Append(',');
                    sb.Append(Csv(r.OwnerFile)).Append(',');
                    sb.Append(Csv(r.OwnerFolder)).Append(',');
                    sb.Append(Csv(r.CommandLine));
                    sb.AppendLine();
                }
                File.WriteAllText(dlg.FileName, sb.ToString(), new UTF8Encoding(true));
                _lblMsg.Text = "已导出：" + dlg.FileName;
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "导出失败：" + ex.Message, "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private static string Csv(string s)
        {
            if (s == null) return "";
            if (s.IndexOf(',') >= 0 || s.IndexOf('"') >= 0 || s.IndexOf('\n') >= 0)
                return "\"" + s.Replace("\"", "\"\"") + "\"";
            return s;
        }

        private void RestartAsAdmin()
        {
            if (_isAdmin)
            {
                MessageBox.Show(this, "当前已经是管理员权限。", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo(Application.ExecutablePath);
                psi.UseShellExecute = true;
                psi.Verb = "runas";
                Process.Start(psi);
                Application.Exit();
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "提权失败：" + ex.Message, "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private void SetBusy(bool busy, string message)
        {
            _busy = busy;
            _btnRefresh.Enabled = !busy;
            _btnScan.Enabled = !busy;
            _btnExport.Enabled = !busy;
            this.Cursor = busy ? Cursors.WaitCursor : Cursors.Default;
            if (!string.IsNullOrEmpty(message)) _lblMsg.Text = message;
        }
    }

    // ---------------------------------------------------------------- 入口

    internal static class Program
    {
        [STAThread]
        private static int Main(string[] args)
        {
            if (args.Length > 0)
            {
                string mode = args[0].ToLowerInvariant();
                try { Console.OutputEncoding = Encoding.UTF8; }
                catch { }
                if (mode == "--dump") return Dump(false);
                if (mode == "--all") return Dump(true);
                if (mode == "--free")
                {
                    int from = 8000, to = 8100;
                    if (args.Length >= 3) { int.TryParse(args[1], out from); int.TryParse(args[2], out to); }
                    return DumpFree(from, to);
                }
                if (mode == "--shot")
                {
                    string path = args.Length >= 2 ? args[1] : "界面预览.png";
                    return Shot(path);
                }
                if (mode == "--selftest") return SelfTest();
            }

            Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
            Application.ThreadException += delegate(object s, System.Threading.ThreadExceptionEventArgs e)
            {
                WriteLog("UI异常：" + e.Exception);
                MessageBox.Show("程序出错：" + e.Exception.Message, "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            };
            AppDomain.CurrentDomain.UnhandledException += delegate(object s, UnhandledExceptionEventArgs e)
            {
                WriteLog("未处理异常：" + e.ExceptionObject);
            };

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
            return 0;
        }

        private static int Shot(string path)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            MainForm f = new MainForm(false);
            f.StartPosition = FormStartPosition.Manual;
            f.Location = new Point(0, 0);
            f.Show();
            Application.DoEvents();
            f.LoadDataSync();
            Application.DoEvents();
            System.Threading.Thread.Sleep(500);
            Application.DoEvents();
            using (Bitmap bmp = new Bitmap(f.Width, f.Height))
            {
                f.DrawToBitmap(bmp, new Rectangle(0, 0, f.Width, f.Height));
                bmp.Save(path, System.Drawing.Imaging.ImageFormat.Png);
            }
            f.Close();
            return 0;
        }

        internal static void WriteLog(string text)
        {
            try
            {
                string dir = AppDomain.CurrentDomain.BaseDirectory;
                File.AppendAllText(Path.Combine(dir, "运行日志.txt"),
                    DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "  " + text + "\r\n", Encoding.UTF8);
            }
            catch { }
        }

        private static int SelfTest()
        {
            int pass = 0, fail = 0;
            Action<bool, string> check = delegate(bool ok, string name)
            {
                Console.WriteLine((ok ? "[通过] " : "[失败] ") + name);
                if (ok) pass++; else fail++;
            };

            List<string> t1 = NetScanner.SplitCommandLine("\"C:\\Program Files\\a b\\x.exe\" --flag \"D:\\d d\\s.py\"");
            check(t1.Count == 3 && t1[0] == "C:\\Program Files\\a b\\x.exe" && t1[2] == "D:\\d d\\s.py", "命令行拆分");

            string r1 = NetScanner.FindRunTarget("C:\\Python39\\python.exe",
                "\"C:\\Python39\\python.exe\" \"D:\\bot\\bot.py\" --config c.ini");
            check(r1 == "D:\\bot\\bot.py", "python 脚本识别");

            string r2 = NetScanner.FindRunTarget("C:\\Windows\\System32\\cmd.exe", "cmd.exe /c \"E:\\work\\start.bat\"");
            check(r2 == "E:\\work\\start.bat", "bat 脚本识别");

            string r3 = NetScanner.FindRunTarget("C:\\app\\server.exe", "server.exe -p 8080");
            check(r3 == null, "普通程序不误判");

            string r4 = NetScanner.FindRunTarget("C:\\node\\node.exe", "\"C:\\node\\node.exe\" app.js --port 3000");
            check(r4 == "app.js", "node 相对脚本识别");

            Console.WriteLine("通过 " + pass + "，失败 " + fail);
            return fail == 0 ? 0 : 1;
        }

        private static int Dump(bool includeAll)
        {
            string error;
            List<PortRow> rows = NetScanner.CollectPorts(includeAll, out error);
            Console.WriteLine("端口\t协议\t地址\t状态\tPID\t进程名\t占用文件\t所在文件夹\t命令行");
            foreach (PortRow r in rows)
            {
                Console.WriteLine(r.Port + "\t" + r.Proto + "\t" + r.Address + "\t" + r.State + "\t" + r.Pid + "\t"
                    + (r.ProcessName ?? "") + "\t" + (r.OwnerFile ?? "") + "\t" + (r.OwnerFolder ?? "") + "\t" + (r.CommandLine ?? ""));
            }
            Console.WriteLine("TOTAL\t" + rows.Count);
            return 0;
        }

        private static int DumpFree(int from, int to)
        {
            FreeScanResult r = NetScanner.FindFreePorts(from, to, null);
            Console.WriteLine("范围\t" + from + "-" + to);
            Console.WriteLine("空闲\t" + r.Free.Count);
            Console.WriteLine("保留\t" + r.Reserved.Count);
            Console.WriteLine("占用\t" + r.Occupied.Count);
            Console.WriteLine("空闲端口\t" + string.Join(",", r.Free.ConvertAll(delegate (int x) { return x.ToString(); }).ToArray()));
            return 0;
        }
    }
}
