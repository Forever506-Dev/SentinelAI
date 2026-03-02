"use client";

import { useState, useRef, useCallback } from "react";
import { FolderSync, Upload, Download, Trash2, File, FileText, Image, Archive, Grid, List, Loader2, Search } from "lucide-react";

interface VaultFile {
  id: string;
  name: string;
  size: number;
  type: string;
  uploadedAt: Date;
  data?: string; // base64
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / (1024 * 1024)).toFixed(1) + " MB";
}

function getFileIcon(type: string) {
  if (type.startsWith("image/")) return Image;
  if (type.includes("zip") || type.includes("tar") || type.includes("rar")) return Archive;
  if (type.includes("text") || type.includes("json") || type.includes("xml")) return FileText;
  return File;
}

export default function FilesPage() {
  const [files, setFiles] = useState<VaultFile[]>([]);
  const [viewMode, setViewMode] = useState<"list" | "grid">("list");
  const [search, setSearch] = useState("");
  const [dragOver, setDragOver] = useState(false);
  const [uploading, setUploading] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const addFiles = useCallback((fileList: FileList) => {
    setUploading(true);
    const promises = Array.from(fileList).map((file) => {
      return new Promise<VaultFile>((resolve) => {
        const reader = new FileReader();
        reader.onload = () => {
          resolve({
            id: crypto.randomUUID(),
            name: file.name,
            size: file.size,
            type: file.type || "application/octet-stream",
            uploadedAt: new Date(),
            data: reader.result as string,
          });
        };
        reader.readAsDataURL(file);
      });
    });

    Promise.all(promises).then((newFiles) => {
      setFiles((prev) => [...newFiles, ...prev]);
      setUploading(false);
    });
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    if (e.dataTransfer.files.length > 0) addFiles(e.dataTransfer.files);
  }, [addFiles]);

  const handleDownload = (file: VaultFile) => {
    if (!file.data) return;
    const a = document.createElement("a");
    a.href = file.data;
    a.download = file.name;
    a.click();
  };

  const handleDelete = (id: string) => {
    setFiles((prev) => prev.filter((f) => f.id !== id));
  };

  const filtered = files.filter((f) => f.name.toLowerCase().includes(search.toLowerCase()));

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <FolderSync className="w-6 h-6 text-sentinel-400" />
            File Vault
          </h1>
          <p className="text-sm text-cyber-muted mt-1">
            Secure file sharing &middot; {files.length} files stored locally
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setViewMode(viewMode === "list" ? "grid" : "list")}
            className="btn-secondary text-xs px-3 py-1.5 flex items-center gap-1.5"
          >
            {viewMode === "list" ? <Grid className="w-3.5 h-3.5" /> : <List className="w-3.5 h-3.5" />}
            {viewMode === "list" ? "Grid" : "List"}
          </button>
          <button
            onClick={() => fileInputRef.current?.click()}
            className="btn-primary text-xs px-3 py-1.5 flex items-center gap-1.5"
          >
            <Upload className="w-3.5 h-3.5" />
            Upload
          </button>
          <input
            ref={fileInputRef}
            type="file"
            multiple
            className="hidden"
            onChange={(e) => e.target.files && addFiles(e.target.files)}
          />
        </div>
      </div>

      {/* Search */}
      <div className="relative max-w-md">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-cyber-muted" />
        <input
          type="text"
          placeholder="Search files..."
          className="input-terminal pl-10"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>

      {/* Drop zone */}
      <div
        onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
        className={
          "border-2 border-dashed rounded-xl p-8 text-center transition-all duration-200 " +
          (dragOver
            ? "border-sentinel-500 bg-sentinel-600/5"
            : "border-cyber-border hover:border-cyber-hover")
        }
      >
        {uploading ? (
          <div className="flex items-center justify-center gap-2">
            <Loader2 className="w-5 h-5 text-sentinel-400 animate-spin" />
            <span className="text-sm text-cyber-muted">Processing files...</span>
          </div>
        ) : (
          <>
            <Upload className={"w-8 h-8 mx-auto mb-2 " + (dragOver ? "text-sentinel-400" : "text-cyber-muted/30")} />
            <p className="text-sm text-cyber-muted">
              Drag & drop files here, or{" "}
              <button onClick={() => fileInputRef.current?.click()} className="text-sentinel-400 hover:underline">
                browse
              </button>
            </p>
          </>
        )}
      </div>

      {/* File list */}
      {filtered.length === 0 && files.length === 0 ? (
        <div className="card-cyber text-center py-12">
          <FolderSync className="w-10 h-10 text-cyber-muted/20 mx-auto mb-3" />
          <p className="text-cyber-muted text-sm">No files yet. Upload or drag files to get started.</p>
        </div>
      ) : viewMode === "list" ? (
        <div className="card-cyber overflow-hidden p-0">
          <table className="w-full">
            <thead>
              <tr className="border-b border-cyber-border bg-cyber-surface/50">
                <th className="text-left text-[10px] font-medium text-cyber-muted uppercase tracking-wider px-6 py-3">Name</th>
                <th className="text-left text-[10px] font-medium text-cyber-muted uppercase tracking-wider px-6 py-3">Size</th>
                <th className="text-left text-[10px] font-medium text-cyber-muted uppercase tracking-wider px-6 py-3">Type</th>
                <th className="text-left text-[10px] font-medium text-cyber-muted uppercase tracking-wider px-6 py-3">Uploaded</th>
                <th className="text-left text-[10px] font-medium text-cyber-muted uppercase tracking-wider px-6 py-3">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyber-border/50">
              {filtered.map((file) => {
                const Icon = getFileIcon(file.type);
                return (
                  <tr key={file.id} className="hover:bg-cyber-hover/30 transition-colors group">
                    <td className="px-6 py-3">
                      <div className="flex items-center gap-3">
                        <Icon className="w-4 h-4 text-sentinel-400" />
                        <span className="text-sm text-white truncate max-w-[300px]">{file.name}</span>
                      </div>
                    </td>
                    <td className="px-6 py-3 text-xs text-cyber-muted">{formatSize(file.size)}</td>
                    <td className="px-6 py-3 text-xs text-cyber-muted font-mono">{file.type.split("/").pop()}</td>
                    <td className="px-6 py-3 text-xs text-cyber-muted">{file.uploadedAt.toLocaleString()}</td>
                    <td className="px-6 py-3">
                      <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                        <button onClick={() => handleDownload(file)} className="p-1.5 hover:bg-sentinel-600/10 rounded-lg transition-colors" title="Download">
                          <Download className="w-3.5 h-3.5 text-sentinel-400" />
                        </button>
                        <button onClick={() => handleDelete(file.id)} className="p-1.5 hover:bg-red-500/10 rounded-lg transition-colors" title="Delete">
                          <Trash2 className="w-3.5 h-3.5 text-red-400" />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-3">
          {filtered.map((file) => {
            const Icon = getFileIcon(file.type);
            return (
              <div key={file.id} className="card-cyber p-4 group hover:border-sentinel-600/30 transition-all">
                <div className="flex items-center justify-between mb-3">
                  <Icon className="w-8 h-8 text-sentinel-400/60" />
                  <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                    <button onClick={() => handleDownload(file)} className="p-1 hover:bg-sentinel-600/10 rounded" title="Download">
                      <Download className="w-3 h-3 text-sentinel-400" />
                    </button>
                    <button onClick={() => handleDelete(file.id)} className="p-1 hover:bg-red-500/10 rounded" title="Delete">
                      <Trash2 className="w-3 h-3 text-red-400" />
                    </button>
                  </div>
                </div>
                <p className="text-sm text-white truncate">{file.name}</p>
                <p className="text-[10px] text-cyber-muted mt-1">{formatSize(file.size)}</p>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
