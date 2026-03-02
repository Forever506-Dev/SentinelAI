import pathlib, shutil

base = pathlib.Path(r"F:\SentinelAI\panel\src\app")
auth_dir = base / "(authenticated)"
auth_dir.mkdir(exist_ok=True)

# Create shared layout for all authenticated pages
shared_layout = '''import { Sidebar } from "@/components/ui/sidebar";

export default function AuthenticatedLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar />
      <main className="flex-1 overflow-y-auto p-6">{children}</main>
    </div>
  );
}
'''
(auth_dir / "layout.tsx").write_text(shared_layout, encoding="utf-8")
print("Created (authenticated)/layout.tsx")

# Move each section into the route group, removing old layout.tsx
for section in ["dashboard", "agents", "alerts", "analysis"]:
    src = base / section
    dst = auth_dir / section
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst)
    # Remove the per-section layout (sidebar is in shared layout now)
    layout_file = dst / "layout.tsx"
    if layout_file.exists():
        layout_file.unlink()
        print(f"  Removed {section}/layout.tsx (using shared layout)")
    # Remove old directory
    shutil.rmtree(src)
    print(f"  Moved {section}/ -> (authenticated)/{section}/")

print("Done! Route group created.")
