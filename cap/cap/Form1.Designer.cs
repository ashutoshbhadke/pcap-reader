namespace cap
{
    partial class pcapform
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.loadfile = new System.Windows.Forms.Button();
            this.txtinfo = new System.Windows.Forms.TextBox();
            this.fopen = new System.Windows.Forms.OpenFileDialog();
            this.previous = new System.Windows.Forms.Button();
            this.next = new System.Windows.Forms.Button();
            this.filelabel = new System.Windows.Forms.Label();
            this.SuspendLayout();
            // 
            // loadfile
            // 
            this.loadfile.Location = new System.Drawing.Point(18, 12);
            this.loadfile.Name = "loadfile";
            this.loadfile.Size = new System.Drawing.Size(96, 21);
            this.loadfile.TabIndex = 0;
            this.loadfile.Text = "Load FIle";
            this.loadfile.UseVisualStyleBackColor = true;
            this.loadfile.Click += new System.EventHandler(this.loadfile_Click);
            // 
            // txtinfo
            // 
            this.txtinfo.Location = new System.Drawing.Point(12, 39);
            this.txtinfo.Multiline = true;
            this.txtinfo.Name = "txtinfo";
            this.txtinfo.ReadOnly = true;
            this.txtinfo.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.txtinfo.Size = new System.Drawing.Size(461, 465);
            this.txtinfo.TabIndex = 22;
            // 
            // previous
            // 
            this.previous.Location = new System.Drawing.Point(287, 12);
            this.previous.Name = "previous";
            this.previous.Size = new System.Drawing.Size(85, 21);
            this.previous.TabIndex = 25;
            this.previous.Text = "Previous";
            this.previous.UseVisualStyleBackColor = true;
            this.previous.Click += new System.EventHandler(this.previous_Click);
            // 
            // next
            // 
            this.next.Location = new System.Drawing.Point(389, 12);
            this.next.Name = "next";
            this.next.Size = new System.Drawing.Size(90, 22);
            this.next.TabIndex = 24;
            this.next.Text = "Next";
            this.next.UseVisualStyleBackColor = true;
            this.next.Click += new System.EventHandler(this.next_Click);
            // 
            // filelabel
            // 
            this.filelabel.AutoSize = true;
            this.filelabel.Location = new System.Drawing.Point(122, 16);
            this.filelabel.Name = "filelabel";
            this.filelabel.Size = new System.Drawing.Size(81, 13);
            this.filelabel.TabIndex = 26;
            this.filelabel.Text = "Opened: (none)";
            // 
            // pcapform
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(483, 516);
            this.Controls.Add(this.filelabel);
            this.Controls.Add(this.previous);
            this.Controls.Add(this.next);
            this.Controls.Add(this.txtinfo);
            this.Controls.Add(this.loadfile);
            this.Name = "pcapform";
            this.Text = "PCAP Viewer";
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Button loadfile;
        private System.Windows.Forms.TextBox txtinfo;
        private System.Windows.Forms.OpenFileDialog fopen;
        private System.Windows.Forms.Button previous;
        private System.Windows.Forms.Button next;
        private System.Windows.Forms.Label filelabel;
    }
}

