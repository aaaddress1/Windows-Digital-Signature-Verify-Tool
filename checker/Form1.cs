using Security.WinTrust;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Windows.Forms;

namespace checker
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        [DllImport("wintrust.dll", PreserveSig = true, SetLastError = false)]
        public static extern uint WinVerifyTrust(IntPtr hWnd, IntPtr pgActionID, IntPtr pWinTrustData);

        Process[] pArray;
        bool isHang = true;
        private void Form1_Shown(object sender, EventArgs e)
        {
            Form.CheckForIllegalCrossThreadCalls = false;
            this.listBox1.SelectedIndexChanged += new System.EventHandler(delegate(object o, EventArgs a)
            {
                try
                {
                    Process curr = pArray[this.listBox1.SelectedIndex];
                    richTextBox1.Text = "Target Process = " + curr.ProcessName + " , pid = " + curr.Id + "\n";
                    foreach (ProcessModule i in curr.Modules)
                    {
                        richTextBox1.Text += i.FileVersionInfo.ToString() + "path: " + i.FileName + "\n";

                        WinVerifyTrustResult result = WinTrust.VerifySignatureResult(i.FileName);
                        richTextBox1.Text += ("簽章確認結果:\t"+result + "\n");
                        richTextBox1.Text += "==============================\n";
                    }
                }
                catch (Exception ex)
                {
                    richTextBox1.Text = ex.ToString();
                }
            });
            this.listBox1.GotFocus += new System.EventHandler(delegate(Object o, EventArgs a)
            {
                isHang = true;
            });
            this.listBox1.LostFocus += new System.EventHandler(delegate(Object o, EventArgs a)
            {
                isHang = false;
            });
            (new System.Threading.Thread(() =>
            {
                while (true)
                {
                    if (isHang) continue;
                    if (pArray == null ||Process.GetProcesses().Length != pArray.Length)
                    {
                        pArray = Process.GetProcesses();
                        this.Invoke(new MethodInvoker(() => listBox1.Items.Clear()));
                        foreach (var i in pArray)
                            this.Invoke(new MethodInvoker(() => listBox1.Items.Add(i.Id + "\t" + i.ProcessName)));
                    }
                    else
                    {
                        System.Threading.Thread.Sleep(1000);
                        continue;
                    }
    
                }
            }) { IsBackground = true }).Start();
            richTextBox1.Focus();
        }

     


    }
}
