                                                        /*PCAP Viewer*/
//Author: Ashutosh Bhadke

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.IO;
using System.Collections;

namespace cap
{
    
    public partial class pcapform : Form
    {
        BinaryReader b;
        FileStream bfile;
        format s = new format();
             
        double time;
        class format
        {
            public byte[] global = new byte[24] { 0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 };
            public uint count=0; 
            public uint time;
            public uint msec;
            public uint length;
            public String eth_dest;
            public String eth_src;
            public uint ptype;
            public uint plength; 
            public String srcip;
            public String destip;
            public uint srcport;
            public uint destport;
            public uint seqno;
            public uint ackno;
            public double hlen;
            public Boolean syn, fin, ack, urg, psh, rst;
            public uint wsize;
        }

        public pcapform()
        {
            InitializeComponent();
            next.Enabled = false;
            previous.Enabled = false;
        }

        private void loadfile_Click(object sender, EventArgs e)
        {
            fopen.ShowDialog();

            String filename = fopen.FileName;
            try
            {
                if (bfile != null)
                    bfile.Close();
                bfile = File.Open(filename, FileMode.Open);
            }
            catch (Exception e1)
            {
                string s1 = e1.Message;

                Exception e2=e1.InnerException;
                while (e2!=null)
                {
                    s1 = s1 + "\n" + e2.Message;
                    e2=e1.InnerException;
                }
                MessageBox.Show(s1, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            if (!bfile.CanRead)
                return;
            b = new BinaryReader(bfile);
            filelabel.Text = "Opened: "+fopen.SafeFileName;
            next.Enabled = false;
            previous.Enabled = false;
            
            
                int flag = 0;
                s=new format();
                byte[] b1 = new byte[32];
                byte[] glob = new byte[24];

                glob = b.ReadBytes(24);

                for (int i = 0; i < 24; i++)
                {
                    if (glob[i] == s.global[i])
                        continue;
                    else
                        flag = 1;
                }

                if (flag == 1)
                {
                    MessageBox.Show("Global Header Error. File is not a valid CAP/PCAP file", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    txtinfo.Clear();
                    filelabel.Text = "Opened: (none)";
                }
                else
                {
                    next.Enabled = true;
                    previous.Enabled = true;
                    display(true);

                }
        }

        private void next_Click(object sender, EventArgs e)
        {
           display(true);
        }

        public void display(bool skip)
        {
            txtinfo.Visible = skip;

            byte[] b1 = new byte[128];

            uint packlen;

            if(b.PeekChar()!=-1)
           {
                txtinfo.Text = "";
            
            s.count++;
            txtinfo.AppendText("Packet No. : " + s.count.ToString()+"\n");      //Packet Number
                
            packlen = 0;
            b1 = b.ReadBytes(4);
            s.time = BitConverter.ToUInt32(b1, 0);      //seconds
            
            b1 = b.ReadBytes(4);
            s.msec = BitConverter.ToUInt32(b1, 0);      //microsecs

            String temp1 = s.time.ToString()+"."+s.msec.ToString();
            if (s.count == 1)
            {
                time = double.Parse(temp1);
                temp1 = "0.000000";
            }
            else
            {
                double d1 = double.Parse(temp1);
                d1 -= time;
                d1 = Math.Round(d1, 6);
                temp1 = d1.ToString("F6");
            }
            txtinfo.AppendText("Arrival Time : " + temp1 + "\n");
            
            b1 = b.ReadBytes(4);
            s.length = BitConverter.ToUInt32(b1, 0);        //Data length
            txtinfo.AppendText("Packet Length : " + s.length.ToString() + "\n");
            
            b1 = b.ReadBytes(4);                        //double storage

            txtinfo.AppendText("Ethernet\n");
            b1 = b.ReadBytes(6);
            packlen = packlen + 6;
            s.eth_dest = BitConverter.ToString(b1);      //ethernet destination
            txtinfo.AppendText("\t Destination : " + s.eth_dest.ToString() + "\n");
            
            
            b1 = b.ReadBytes(6);
            packlen = packlen + 6;
            s.eth_src = BitConverter.ToString(b1);      //ethernet source
            txtinfo.AppendText("\t Source : " + s.eth_src.ToString() + "\n");
            

            b1 = b.ReadBytes(2);
            packlen = packlen + 2;
            s.ptype = BitConverter.ToUInt16(b1, 0);      //type of packet

            if (b1[0]==0x08 && b1[1]==0x00)
                txtinfo.AppendText("\t IP Type : IP\n");
            else if (b1[0] == 0x20 && b1[1] == 0x00)
                txtinfo.AppendText("\t IP Type : XEROX PUP\n");
            else if (b1[0] == 0x08 && b1[1] == 0x06)
                txtinfo.AppendText("\t IP Type : ARP\n");
            else if (b1[0] == 0x80 && b1[1] == 0x35)
                txtinfo.AppendText("\t IP Type : RARP\n");

            byte ver;
            b1 = b.ReadBytes(2); // IP version & DSF
            ver = b1[0];
            ver = (byte)(ver >> 4);
            txtinfo.AppendText("Internet Protocol\n");
            txtinfo.AppendText("\t IP Version : "+ver.ToString() + "\n");

            ver = b1[0];
            ver &= 0x0f;
            int tempheader = ver;
            tempheader *= 4;
            txtinfo.AppendText("\t Header Length : " + tempheader.ToString() + "\n");
            ver = b1[1];
            ver &= 0x01;
            if (ver==0x00)
                txtinfo.AppendText("\t ECN-CE : 0\n");
            else
                txtinfo.AppendText("\t ECN-CE : 1\n");
            ver = b1[1];
            ver &= 0x02;
            if (ver == 0x00)
                txtinfo.AppendText("\t ECN Capable Transport : 0\n");
            else
                txtinfo.AppendText("\t ECN Capable Transport : 1\n");

            ver = b1[1];
            ver &= 0xfc;
            txtinfo.AppendText("\t Differenctiated Service Codepoint : " + ver.ToString() + "\n");

            packlen = packlen + 2;
            b1 = b.ReadBytes(2);
            packlen = packlen + 2;
            if (BitConverter.IsLittleEndian)
                Array.Reverse(b1);
            s.plength = BitConverter.ToUInt16(b1, 0);             // packet length
            txtinfo.AppendText("\t Total Length : " + s.plength.ToString() + "\n");

            b1 = b.ReadBytes(2);        // Identification
            txtinfo.AppendText("\t Identification : " + BitConverter.ToString(b1).Replace("-", string.Empty) + "\n");

            txtinfo.AppendText("\t IP Header Flags\n");
            b1 = b.ReadBytes(2);

            ver = b1[0];
            ver &= 0x80;
            if (ver == 0x80)
                txtinfo.AppendText("\t\t Reserved Bit : Set\n");        //Reserved flag
            else
                txtinfo.AppendText("\t\t Reserved Bit : Not Set\n");

            ver = b1[0];
            ver &= 0x40;
            if (ver == 0x00)
                txtinfo.AppendText("\t\t Do not fragment : Not Set\n"); //Do not Fragment flag
            else
                txtinfo.AppendText("\t\t Do not fragment : Set\n");

            ver = b1[0];
            ver &= 0x20;
            if (ver == 0x00)
                txtinfo.AppendText("\t\t More fragment : Not Set\n");   // More fragment flag
            else
                txtinfo.AppendText("\t\t More fragment : Set\n");

            b1[0] &= 0x01;
            b1[1] &= 0xff;
            txtinfo.AppendText("\t Fragment Offset : " + BitConverter.ToUInt16(b1, 0).ToString() + "\n");   //Fragmentation Offset

            b1 = b.ReadBytes(1);
            Byte []arr =  new Byte[2];
            arr[0] = b1[0];
            arr[1] = 0x00;
            txtinfo.AppendText("\t Time to Live : " + BitConverter.ToUInt16(arr, 0).ToString() + "\n");     //TTL

            b1 = b.ReadBytes(1);
            txtinfo.AppendText("\t Protocol Number : " + b1[0].ToString() + "\n");      //Protocol

            b1 = b.ReadBytes(2);
            txtinfo.AppendText("\t Checksum : " + BitConverter.ToString(b1).Replace("-", string.Empty) + "\n");     // IP Checksum

            packlen = packlen + 8;
            
            s.srcip = "";
            decimal temp;
            for (int i = 0; i < 4; i++)                 //src ip
            {
                temp = b.ReadByte();
                s.srcip = s.srcip + temp.ToString();
                if (i != 3)
                    s.srcip = s.srcip + '.';
            }
            packlen = packlen + 4;

            txtinfo.AppendText("\t Source IP: "+s.srcip+"\n");

            s.destip = "";
            for (int i = 0; i < 4; i++)                 //dest ip
            {
                temp = b.ReadByte();
                s.destip = s.destip + temp.ToString();
                if (i != 3)
                    s.destip = s.destip + '.';
            }
            packlen = packlen + 4;
            txtinfo.AppendText("\t Destination IP: " + s.destip + "\n");

            b1 = b.ReadBytes(2);
            packlen = packlen + 2;
            if (BitConverter.IsLittleEndian)
                Array.Reverse(b1);

            txtinfo.AppendText("Transmission Control Protocol\n");
            s.srcport = BitConverter.ToUInt16(b1, 0);               //source port
            txtinfo.AppendText("\t Source Port: " + s.srcport.ToString() + "\n");
            
            b1 = b.ReadBytes(2);
            packlen = packlen + 2;
            if (BitConverter.IsLittleEndian)
                Array.Reverse(b1);
            s.destport = BitConverter.ToUInt16(b1, 0);              //Dest port
            txtinfo.AppendText("\t Destination Port: " + s.destport.ToString() + "\n");

            b1 = b.ReadBytes(4);
            packlen = packlen + 4;
            if (BitConverter.IsLittleEndian)
                Array.Reverse(b1);
            s.seqno = BitConverter.ToUInt32(b1, 0);    //Sequence number
            txtinfo.AppendText("\t Sequence Number: " + s.seqno.ToString() + "\n");

            b1 = b.ReadBytes(4);
            packlen = packlen + 4;
            if (BitConverter.IsLittleEndian)
                Array.Reverse(b1);
            s.ackno = BitConverter.ToUInt32(b1, 0);    //Acknoledgement number
            txtinfo.AppendText("\t Acknowledgement Number: " + s.ackno.ToString() + "\n");

            uint[] len = new uint[4];
            b1 = b.ReadBytes(1);                       // Header length
            packlen = packlen + 1;

            BitArray bits = new BitArray(b1);
            int j = 0;
            s.hlen = 0;
            for (int i = 4; i < 8; i++)
            {
                if (bits[i])
                    s.hlen = s.hlen + Math.Pow(2.0, j);
                j++;
            }
            s.hlen = s.hlen * 4;                                        //header length
            txtinfo.AppendText("\t Header Length: " + s.hlen.ToString() + "\n");

            b1 = b.ReadBytes(1);
            packlen = packlen + 1;
            bits = new BitArray(b1);

            s.fin = bits[0]; s.syn = bits[1]; s.rst = bits[2];        //flags
            s.psh = bits[3]; s.ack = bits[4]; s.urg = bits[5];

            txtinfo.AppendText("\t TCP Flags \n");
     
            txtinfo.AppendText("\t\t FIN : "+ s.fin +" \n");
            txtinfo.AppendText("\t\t SYN : " + s.syn + " \n");
            txtinfo.AppendText("\t\t RST : " + s.rst + " \n");
            txtinfo.AppendText("\t\t PSH : " + s.psh + " \n");
            txtinfo.AppendText("\t\t ACK : " + s.ack + " \n");
            txtinfo.AppendText("\t\t URG : " + s.urg + " \n");

            b1 = b.ReadBytes(2);
            packlen = packlen + 2;
            if (BitConverter.IsLittleEndian)
                Array.Reverse(b1);
            s.wsize = BitConverter.ToUInt16(b1, 0);             // windows size
            txtinfo.AppendText("\t Window Size : " + s.wsize.ToString() + " \n");

            b1 = b.ReadBytes(2);    // TCP Checksum 
            txtinfo.AppendText("\t Checksum : " + BitConverter.ToString(b1).Replace("-", string.Empty) + "\n");

            packlen = packlen + 2;

            uint len1 = s.length - packlen;
            if (len1<65537)
                b1 = b.ReadBytes((int)len1);

            txtinfo.SelectionStart = 1;
            txtinfo.ScrollToCaret();
            txtinfo.Refresh();
           }       
        }

        private void previous_Click(object sender, EventArgs e)
        {
            if (bfile != null)
            {
                bfile.Seek(24, SeekOrigin.Begin);
                uint len = s.count;
                s.count = 0;
                for (uint i=1;i<len-1;i++)
                    display(false);
                display(true);
                
            }
        }
    }
}    