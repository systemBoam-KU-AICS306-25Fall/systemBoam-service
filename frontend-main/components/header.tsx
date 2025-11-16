"use client"

import { Shield } from "lucide-react"

export function Header() {
  return (
    <header className="border-b border-border bg-card">
      <div className="container mx-auto px-4 py-4">
        <div className="flex items-center justify-between">
          {/* Logo */}
          <div className="flex items-center gap-2">
            <Shield className="h-8 w-8 text-primary" />
            <span className="text-foreground font-bold text-2xl">CVE Monitor</span>
          </div>

          {/* Center - Empty */}
          <div className="flex-1" />

          {/* Right side - User menu, notifications, feed button */}
        </div>
      </div>
    </header>
  )
}
