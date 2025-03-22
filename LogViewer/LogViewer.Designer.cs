namespace LogViewer {
    partial class LogViewer {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing) {
            if (disposing && (components != null)) {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent() {
            this.LogDgv = new System.Windows.Forms.DataGridView();
            this.Type = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.Timestamp = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.LogText = new System.Windows.Forms.DataGridViewTextBoxColumn();
            ((System.ComponentModel.ISupportInitialize)(this.LogDgv)).BeginInit();
            this.SuspendLayout();
            // 
            // LogDgv
            // 
            this.LogDgv.AllowUserToAddRows = false;
            this.LogDgv.AllowUserToDeleteRows = false;
            this.LogDgv.AutoSizeRowsMode = System.Windows.Forms.DataGridViewAutoSizeRowsMode.AllCells;
            this.LogDgv.ColumnHeadersHeightSizeMode = System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode.AutoSize;
            this.LogDgv.Columns.AddRange(new System.Windows.Forms.DataGridViewColumn[] {
            this.Type,
            this.Timestamp,
            this.LogText});
            this.LogDgv.Location = new System.Drawing.Point(12, 12);
            this.LogDgv.Name = "LogDgv";
            this.LogDgv.ReadOnly = true;
            this.LogDgv.RowHeadersWidth = 82;
            this.LogDgv.RowTemplate.Height = 33;
            this.LogDgv.Size = new System.Drawing.Size(1713, 1003);
            this.LogDgv.TabIndex = 0;
            // 
            // Type
            // 
            this.Type.HeaderText = "Log Type";
            this.Type.MinimumWidth = 10;
            this.Type.Name = "Type";
            this.Type.ReadOnly = true;
            this.Type.Width = 200;
            // 
            // Timestamp
            // 
            this.Timestamp.HeaderText = "Timestamp";
            this.Timestamp.MinimumWidth = 10;
            this.Timestamp.Name = "Timestamp";
            this.Timestamp.ReadOnly = true;
            this.Timestamp.Width = 200;
            // 
            // LogText
            // 
            this.LogText.AutoSizeMode = System.Windows.Forms.DataGridViewAutoSizeColumnMode.ColumnHeader;
            this.LogText.HeaderText = "Log Text";
            this.LogText.MinimumWidth = 1200;
            this.LogText.Name = "LogText";
            this.LogText.ReadOnly = true;
            this.LogText.Width = 1200;
            // 
            // LogViewer
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(12F, 25F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(1737, 1027);
            this.Controls.Add(this.LogDgv);
            this.Name = "LogViewer";
            this.Text = "Form1";
            this.Load += new System.EventHandler(this.LogViewer_Load);
            ((System.ComponentModel.ISupportInitialize)(this.LogDgv)).EndInit();
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.DataGridView LogDgv;
        private System.Windows.Forms.DataGridViewTextBoxColumn Type;
        private System.Windows.Forms.DataGridViewTextBoxColumn Timestamp;
        private System.Windows.Forms.DataGridViewTextBoxColumn LogText;
    }
}

