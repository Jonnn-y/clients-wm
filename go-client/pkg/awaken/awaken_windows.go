package awaken

import (
	"encoding/json"
	"fmt"
	"go-client/global"
	"go-client/pkg/autoit"
	"go-client/pkg/config"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"go.uber.org/zap"
	"golang.org/x/sys/windows"
)

var (
	mu               sync.Mutex
	watermarkProcess *os.Process
	activeRdpCount   int
	rdpWaitGroup     sync.WaitGroup
	pidFileMutex     sync.Mutex
)

type PidFileData struct {
	RdpPids      []int `json:"rdp_pid"`
	WatermarkPid int   `json:"watermark_pid"`
	ClientPids   []int `json:"client_pid"`
}

type ProcessType string

const (
	ProcessTypeRDP       ProcessType = "rdp"
	ProcessTypeWatermark ProcessType = "watermark"
)

func EnsureDirExist(path string) {
	if fi, err := os.Stat(path); err == nil && fi.IsDir() {
		return
	}
	if err := os.MkdirAll(path, os.ModePerm); err != nil {
		global.LOG.Error(err.Error())
	}
}

func getNavicatURL(connectInfo map[string]string) string {
	re := regexp.MustCompile(`@(.+)$`)
	matches := re.FindStringSubmatch(connectInfo["name"])
	name := connectInfo["username"]
	if len(matches) > 1 {
		name = matches[1]
	}
	url := fmt.Sprintf("navicat://conn.%s?Conn.Host=%s&Conn.Name=%s&Conn.Port=%s&Conn.Username=%s",
		connectInfo["protocol"], connectInfo["host"], name, connectInfo["port"], connectInfo["username"])
	switch connectInfo["protocol"] {
	case "oracle":
		url = strings.Replace(url, "conn.oracle", "conn.ora", 1)
		url += fmt.Sprintf("&Conn.ServiceName=%s&Conn.ServiceNameType=ServiceName&Conn.ConnectionMode=Basic", connectInfo["dbname"])
	case "sqlserver":
		url = strings.Replace(url, "conn.sqlserver", "conn.mssql", 1)
		url += fmt.Sprintf("&Conn.AuthenticationType=Default&Conn.InitialDatabase=%s", connectInfo["dbname"])
	case "postgresql":
		url = strings.Replace(url, "conn.postgresql", "conn.pgsql", 1)
		url += fmt.Sprintf("&Conn.InitialDatabase=%s", connectInfo["dbname"])
	}

	pattern := regexp.MustCompile(`[\^(){}~]`)
	url = pattern.ReplaceAllStringFunc(url, func(match string) string {
		return fmt.Sprintf("{%s}", match)
	})
	return url
}

func getCommandFromArgs(connectInfo map[string]string, argFormat string) string {
	for key, value := range connectInfo {
		argFormat = strings.Replace(argFormat, "{"+key+"}", value, 1)
	}
	return argFormat
}

func handleRDP(r *Rouse, filePath string, cfg *config.AppConfig) {
	watermarkPid := handleWatermark(r)

	if watermarkPid <= 0 {
		global.LOG.Error("水印程序启动失败，无法获取有效PID，取消启动RDP进程")
		return
	}
	//time.Sleep(300 * time.Millisecond)
	global.LOG.Info("水印程序PID:", zap.Int("pid", watermarkPid))
	cmd := exec.Command("C:\\WINDOWS\\system32\\mstsc.exe", filePath)
	err := cmd.Start()
	if err != nil {
		global.LOG.Error("启动RDP进程失败:", zap.Error(err))
		return
	}
	rdpPid := cmd.Process.Pid
	r.ProcessID = rdpPid
	r.Process = cmd.Process
	global.LOG.Info("RDP进程启动成功", zap.Int("pid", rdpPid))

	savePidFile(rdpPid, watermarkPid, os.Getpid())

	rdpWaitGroup.Add(1)

	startRDPMonitor(r, uint32(rdpPid))

	rdpWaitGroup.Wait()
}

func processExists(pid uint32) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION,
		false, pid)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)

	var exitCode uint32
	if err := windows.GetExitCodeProcess(h, &exitCode); err != nil {
		return false
	}
	return exitCode == 259
}

func startProcessMonitor(r *Rouse, processType ProcessType, pid uint32, onExit func(pid uint32)) {

	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer func() {
			ticker.Stop()
			if r := recover(); r != nil {
				global.LOG.Error("进程监控goroutine异常", zap.Any("recover", r), zap.Uint32("pid", pid), zap.String("type", string(processType)))
			}
		}()

		global.LOG.Info("进入进程监听循环", zap.String("type", string(processType)), zap.Uint32("pid", pid))

		for {
			time.Sleep(500 * time.Millisecond)
			//global.LOG.Info("进程监听中", zap.String("type", string(processType)), zap.Uint32("pid", pid))

			if !processExists(pid) {
				global.LOG.Info("进程已退出", zap.String("type", string(processType)), zap.Uint32("pid", pid))

				if onExit != nil {
					onExit(pid)
				}

				switch processType {
				case ProcessTypeRDP:
					updatePidFileOnRdpExit(pid)
					rdpWaitGroup.Done()
				case ProcessTypeWatermark:
					updatePidFileOnWatermarkExit()

					if hasActiveRDPProcesses() {
						global.LOG.Info("检测到仍有活跃的RDP进程，但水印进程已退出，准备重新启动水印")
						killProcessTree(int(pid))
						restartedPid := handleWatermark(r)
						global.LOG.Info("水印进程已重新启动", zap.Int("pid", restartedPid))
					} else {
						global.LOG.Info("没有活跃的RDP进程，不需要重新启动水印")
					}
				}
				return
			}
		}
	}()
}

func hasActiveRDPProcesses() bool {
	data, _ := getPidFileData()

	for _, rdpPid := range data.RdpPids {
		if processExists(uint32(rdpPid)) {
			global.LOG.Info("发现活跃的RDP进程", zap.Int("pid", rdpPid))
			return true
		}
	}

	if isMstscProcessRunning() {
		global.LOG.Info("发现未在PID文件中记录的mstsc.exe进程")
		return true
	}

	return false
}

func isMstscProcessRunning() bool {
	hSnapshot, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		global.LOG.Error("创建进程快照失败", zap.Error(err))
		return false
	}
	defer syscall.CloseHandle(hSnapshot)

	var pe32 syscall.ProcessEntry32
	pe32.Size = uint32(unsafe.Sizeof(pe32))

	if err := syscall.Process32First(hSnapshot, &pe32); err != nil {
		global.LOG.Error("获取进程信息失败", zap.Error(err))
		return false
	}

	for {
		exeName := syscall.UTF16ToString(pe32.ExeFile[:])
		if strings.EqualFold(exeName, "mstsc.exe") {
			return true
		}

		if err := syscall.Process32Next(hSnapshot, &pe32); err != nil {
			break
		}
	}

	return false
}

func updatePidFileOnRdpExit(rdpPid uint32) {
	pidFileMutex.Lock()
	defer pidFileMutex.Unlock()

	data, err := getPidFileData()
	if err != nil {
		global.LOG.Error("读取PID文件失败", zap.Error(err))
		return
	}

	newRdpPids := []int{}
	newClientPids := []int{}
	for _, p := range data.RdpPids {
		if uint32(p) != rdpPid {
			newRdpPids = append(newRdpPids, p)
		}
	}
	clientPid := os.Getpid()
	for _, p := range data.ClientPids {
		if p != clientPid {
			newClientPids = append(newClientPids, p)
		}
	}
	data.RdpPids = newRdpPids
	data.ClientPids = newClientPids

	content, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		global.LOG.Error("序列化PID数据失败", zap.Error(err))
		return
	}

	if err := ioutil.WriteFile(getPidFilePath(), content, 0644); err != nil {
		global.LOG.Error("写入PID文件失败", zap.Error(err), zap.String("path", getPidFilePath()))
		return
	}

	if len(newRdpPids) == 0 && data.WatermarkPid != 0 {
		killProcessTree(data.WatermarkPid)
		data.WatermarkPid = 0
		content, _ := json.MarshalIndent(data, "", "  ")
		ioutil.WriteFile(getPidFilePath(), content, 0644)
	}
}

func updatePidFileOnWatermarkExit() {
	pidFileMutex.Lock()
	defer pidFileMutex.Unlock()

	data, err := getPidFileData()
	if err != nil {
		global.LOG.Error("读取PID文件失败", zap.Error(err))
		return
	}

	data.WatermarkPid = 0
	content, _ := json.MarshalIndent(data, "", "  ")
	ioutil.WriteFile(getPidFilePath(), content, 0644)
}

func startRDPMonitor(r *Rouse, rdpPid uint32) {
	startProcessMonitor(r, ProcessTypeRDP, rdpPid, nil)
}

func startWatermarkMonitor(r *Rouse, watermarkPid uint32) {
	startProcessMonitor(r, ProcessTypeWatermark, watermarkPid, nil)
}

func handleWatermark(r *Rouse) int {
	var appPath string
	var username string

	mu.Lock()
	defer mu.Unlock()

	data, _ := getPidFileData()
	if data.WatermarkPid != 0 {
		if processExists(uint32(data.WatermarkPid)) {
			global.LOG.Info("发现已运行的水印进程", zap.Int("pid", data.WatermarkPid))
			return data.WatermarkPid
		}
	}

	content := r.File.Content
	prefix := "username:s:"
	start := strings.Index(content, prefix)
	if start != -1 {
		afterPrefix := content[start+len(prefix):]
		end := strings.Index(afterPrefix, "|")
		if end != -1 {
			username = afterPrefix[:end]
			global.LOG.Info("提取到用户名", zap.String("username", username))
		}
	}

	currentPath := filepath.Dir(os.Args[0])
	appPath = filepath.Join(currentPath, "wm.exe")
	global.LOG.Info("当前水印路径是", zap.String("appPath", appPath))
	cmdWm := exec.Command(appPath, username, getPidFilePath())
	err := cmdWm.Start()
	if err != nil {
		global.LOG.Error("启动水印进程失败:", zap.Error(err))
		return 0
	}
	watermarkPid := cmdWm.Process.Pid

	global.LOG.Info("水印进程启动成功", zap.Int("pid", watermarkPid))

	savePidFile(0, watermarkPid, 0)

	startWatermarkMonitor(r, uint32(watermarkPid))

	watermarkProcess = cmdWm.Process
	return watermarkProcess.Pid
}

func killProcessTree(pid int) error {
	children, err := getChildProcessIDs(pid)
	if err != nil {
		return fmt.Errorf("获取子进程失败: %v", err)
	}

	for _, childPid := range children {
		if err := killProcessTree(childPid); err != nil {
			global.LOG.Warn("终止子进程失败", zap.Int("pid", childPid), zap.Error(err))
		}
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("查找进程失败: %v", err)
	}
	if err := proc.Kill(); err != nil {
		return fmt.Errorf("终止进程失败: %v", err)
	}
	global.LOG.Info("进程已终止", zap.Int("pid", pid))
	return nil
}

func getChildProcessIDs(parentPid int) ([]int, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshot)

	var pe32 windows.ProcessEntry32
	pe32.Size = uint32(unsafe.Sizeof(pe32))

	if err := windows.Process32First(snapshot, &pe32); err != nil {
		return nil, fmt.Errorf("Process32First failed: %v", err)
	}

	var children []int
	for {
		if int(pe32.ParentProcessID) == parentPid {
			children = append(children, int(pe32.ProcessID))
		}
		if err := windows.Process32Next(snapshot, &pe32); err != nil {
			break
		}
	}
	return children, nil
}

func savePidFile(rdpPid int, watermarkPid int, clientPid int) error {
	dir, _ := os.UserConfigDir()
	pidFilePath := filepath.Join(dir, "jumpserver-client", "pids.json")
	EnsureDirExist(filepath.Dir(pidFilePath))

	data := PidFileData{}
	if _, err := os.Stat(pidFilePath); err == nil {
		content, _ := ioutil.ReadFile(pidFilePath)
		json.Unmarshal(content, &data)
	}

	if rdpPid != 0 {
		found := false
		for _, p := range data.RdpPids {
			if p == rdpPid {
				found = true
				break
			}
		}
		if !found {
			data.RdpPids = append(data.RdpPids, rdpPid)
		}
	}
	data.WatermarkPid = watermarkPid
	if clientPid != 0 {
		found := false
		for _, p := range data.ClientPids {
			if p == clientPid {
				found = true
				break
			}
		}
		if !found {
			data.ClientPids = append(data.ClientPids, clientPid)
		}
	}

	content, _ := json.MarshalIndent(data, "", "  ")
	return ioutil.WriteFile(pidFilePath, content, 0644)
}

func getPidFileData() (PidFileData, error) {
	dir, _ := os.UserConfigDir()
	pidFilePath := filepath.Join(dir, "jumpserver-client", "pids.json")
	data := PidFileData{}
	if _, err := os.Stat(pidFilePath); err == nil {
		content, _ := ioutil.ReadFile(pidFilePath)
		json.Unmarshal(content, &data)
	}
	return data, nil
}

func getPidFilePath() string {
	dir, _ := os.UserConfigDir()
	return filepath.Join(dir, "jumpserver-client", "pids.json")
}

func handleVNC(r *Rouse, cfg *config.AppConfig) *exec.Cmd {
	var appItem *config.AppItem
	appLst := cfg.Windows.RemoteDesktop
	for _, app := range appLst {
		if app.IsSet && app.IsMatchProtocol("vnc") {
			appItem = &app
			break
		}
	}
	if appItem == nil {
		return nil
	}
	connectMap := map[string]string{
		"name":     r.getName(),
		"protocol": r.Protocol,
		"username": r.getUserName(),
		"value":    r.Value,
		"host":     r.Host,
		"port":     strconv.Itoa(r.Port),
	}
	if len(appItem.AutoIt) == 0 {
		return nil
	} else {
		commands := getCommandFromArgs(connectMap, appItem.ArgFormat)
		global.LOG.Error(appItem.Path + " " + commands)
		autoit.LoadAuto()
		autoit.Run(appItem.Path + " " + commands)
		for _, item := range appItem.AutoIt {
			time.Sleep(300 * time.Millisecond)
			switch item.Cmd {
			case "Wait":
				sleepTime, _ := strconv.Atoi(item.Type)
				winTitle := item.Element
				maxRetry := 0
				for {
					ret := autoit.WinWaitActive(winTitle, "", sleepTime)
					time.Sleep(time.Duration(sleepTime) * 100 * time.Millisecond)
					if ret != 0 || maxRetry > 30 {
						break
					}
					maxRetry++
				}
			case "ControlSend":
				maxRetry := 0
				for {
					ret := autoit.ControlSend("", "", item.Element, getCommandFromArgs(connectMap, item.Type))
					time.Sleep(300 * time.Millisecond)
					if ret != 0 || maxRetry > 10 {
						break
					}
					maxRetry++
				}
			case "ControlSetText":
				maxRetry := 0
				for {
					ret := autoit.ControlSetText("", "", item.Element, getCommandFromArgs(connectMap, item.Type))
					time.Sleep(300 * time.Millisecond)
					if ret != 0 || maxRetry > 10 {
						break
					}
					maxRetry++
				}
			case "ControlClick":
				pos := strings.Split(item.Type, ",")
				x, _ := strconv.Atoi(pos[0])
				y, _ := strconv.Atoi(pos[1])
				maxRetry := 0
				for {
					ret := autoit.ControlClick("", "", item.Element, "left", 1, x, y)
					time.Sleep(300 * time.Millisecond)
					if ret != 0 || maxRetry > 10 {
						break
					}
					maxRetry++
				}
			case "SendKey":
				autoit.Send(item.Element)
			}
		}
		return exec.Command("")
	}
}

func handleSSH(r *Rouse, cfg *config.AppConfig) *exec.Cmd {
	var appItem *config.AppItem
	var appLst []config.AppItem
	switch r.Protocol {
	case "ssh", "telnet":
		r.Protocol = "ssh"
		appLst = cfg.Windows.Terminal
	case "sftp":
		appLst = cfg.Windows.FileTransfer
	}

	for _, app := range appLst {
		if app.IsSet && app.IsMatchProtocol(r.Protocol) {
			appItem = &app
			break
		}
	}
	if appItem == nil {
		return nil
	}
	var appPath string
	if appItem.IsInternal {
		currentPath := filepath.Dir(os.Args[0])
		appPath = filepath.Join(currentPath, appItem.Path)
	} else {
		appPath = appItem.Path
	}

	connectMap := map[string]string{
		"name":     r.getName(),
		"protocol": r.Protocol,
		"username": r.getUserName(),
		"value":    r.Value,
		"host":     r.Host,
		"port":     strconv.Itoa(r.Port),
	}
	commands := getCommandFromArgs(connectMap, appItem.ArgFormat)
	if strings.Contains(commands, "*") {
		commands := strings.Split(commands, "*")
		return exec.Command(appPath, commands[0], commands[1])
	} else {
		commands := strings.Split(commands, " ")
		return exec.Command(appPath, commands...)
	}
}

func handleDB(r *Rouse, cfg *config.AppConfig) *exec.Cmd {
	var appItem *config.AppItem
	appLst := cfg.Windows.Databases
	for _, app := range appLst {
		if app.IsSet && app.IsMatchProtocol(r.Protocol) {
			appItem = &app
			break
		}
	}
	if appItem == nil {
		return nil
	}
	appPath := appItem.Path

	connectMap := map[string]string{
		"name":     r.getName(),
		"protocol": r.Protocol,
		"username": r.getUserName(),
		"value":    r.Value,
		"host":     r.Host,
		"port":     strconv.Itoa(r.Port),
		"dbname":   r.DBName,
	}

	if r.Protocol == "oracle" {
		connectMap["dbname"] = r.getUserName()
	}
	if r.Protocol == "sqlserver" && appItem.Name == "dbeaver" {
		connectMap["protocol"] = "mssql_jdbc_ms_new"
	}
	if r.Protocol == "redis" && appItem.Name == "resp" {
		var conList []map[string]string
		ss := make(map[string]string)
		ss["host"] = r.Host
		ss["port"] = strconv.Itoa(r.Port)
		ss["name"] = r.getName()
		ss["auth"] = r.Token.ID + "@" + r.Value
		ss["ssh_agent_path"] = ""
		ss["ssh_password"] = ""
		ss["ssh_private_key_path"] = ""
		ss["timeout_connect"] = "60000"
		ss["timeout_execute"] = "60000"
		conList = append(conList, ss)

		bjson, _ := json.Marshal(conList)
		dir, _ := os.UserConfigDir()
		currentPath := filepath.Join(dir, "jumpserver-client")
		rdmPath := filepath.Join(currentPath, ".rdm")
		EnsureDirExist(rdmPath)
		filePath := filepath.Join(rdmPath, "connections.json")
		global.LOG.Error(filePath)
		err := ioutil.WriteFile(filePath, bjson, os.ModePerm)
		if err != nil {
			global.LOG.Error(err.Error())
			return nil
		}
		connectMap["config_file"] = currentPath

	}
	if appItem.Name == "navicat17" {
		url := getNavicatURL(connectMap)
		connectMap["url"] = url
	}
	if len(appItem.AutoIt) == 0 {
		commands := getCommandFromArgs(connectMap, appItem.ArgFormat)
		if strings.Contains(commands, "*") {
			commands := strings.Split(commands, "*")
			return exec.Command(appPath, commands...)
		} else {
			commands := strings.Split(commands, " ")
			return exec.Command(appPath, commands...)
		}
	} else {
		autoit.LoadAuto()
		autoit.Run(appPath)
		for _, item := range appItem.AutoIt {
			time.Sleep(300 * time.Millisecond)
			switch item.Cmd {
			case "Wait":
				sleepTime, _ := strconv.Atoi(item.Type)
				winTitle := item.Element
				maxRetry := 0
				for {
					ret := autoit.WinWaitActive(winTitle, "", sleepTime)
					time.Sleep(time.Duration(sleepTime) * 100 * time.Millisecond)
					if ret != 0 || maxRetry > 30 {
						break
					}
					maxRetry++
				}
			case "ControlSend":
				maxRetry := 0
				for {
					ret := autoit.ControlSend("", "", item.Element, getCommandFromArgs(connectMap, item.Type))
					time.Sleep(300 * time.Millisecond)
					if ret != 0 || maxRetry > 10 {
						break
					}
					maxRetry++
				}
			case "ControlSetText":
				maxRetry := 0
				for {
					ret := autoit.ControlSetText("", "", item.Element, getCommandFromArgs(connectMap, item.Type))
					time.Sleep(300 * time.Millisecond)
					if ret != 0 || maxRetry > 10 {
						break
					}
					maxRetry++
				}
			case "ControlClick":
				pos := strings.Split(item.Type, ",")
				x, _ := strconv.Atoi(pos[0])
				y, _ := strconv.Atoi(pos[1])
				maxRetry := 0
				for {
					ret := autoit.ControlClick("", "", item.Element, "left", 1, x, y)
					time.Sleep(300 * time.Millisecond)
					if ret != 0 || maxRetry > 10 {
						break
					}
					maxRetry++
				}
			case "SendKey":
				autoit.Send(item.Element)
			}
		}
		return exec.Command("")
	}
}

func handleCommand(r *Rouse, cfg *config.AppConfig) *exec.Cmd {
	cmd := exec.Command(r.Command)
	return cmd
}
