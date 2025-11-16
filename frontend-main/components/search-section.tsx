"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"
import { Search, Tag } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card } from "@/components/ui/card"

type SearchMode = "cve" | "keyword"

// Mock CVE database for search
const allCVEs = [
  { id: "CVE-2025-0001", title: "Apache Log4j Zero-Day", year: 2025 },
  { id: "CVE-2025-0002", title: "Apache Struts Vulnerability", year: 2025 },
  { id: "CVE-2025-0003", title: "Windows Kernel Vulnerability", year: 2025 },
  { id: "CVE-2025-0004", title: "SQL Injection in CMS", year: 2025 },
  { id: "CVE-2025-0005", title: "CMS Authentication Bypass", year: 2025 },
  { id: "CVE-2025-0006", title: "CMS RCE Vulnerability", year: 2025 },
  { id: "CVE-2025-0007", title: "OpenSSL Remote Code Execution", year: 2025 },
  { id: "CVE-2025-0008", title: "VPN Authentication Bypass", year: 2025 },
  { id: "CVE-2025-0009", title: "VPN Encryption Flaw", year: 2025 },
  { id: "CVE-2024-1001", title: "Database Vulnerability", year: 2024 },
  { id: "CVE-2024-1002", title: "Container Escape", year: 2024 },
  { id: "CVE-2023-5001", title: "Browser XSS", year: 2023 },
]

export function SearchSection() {
  const router = useRouter()
  const [mode, setMode] = useState<SearchMode>("cve")
  const [searchQuery, setSearchQuery] = useState("")
  const [searchResults, setSearchResults] = useState<typeof allCVEs>([])
  const [showResults, setShowResults] = useState(false)

  const handleSearch = (query: string) => {
    setSearchQuery(query)

    if (!query.trim()) {
      setSearchResults([])
      setShowResults(false)
      return
    }

    const lowerQuery = query.toLowerCase()
    let results: typeof allCVEs = []

    if (mode === "cve") {
      // Search by CVE ID (supports partial matches like "2025" or "CVE-2025")
      results = allCVEs.filter((cve) => cve.id.toLowerCase().includes(lowerQuery))
    } else {
      // Search by keyword in title
      results = allCVEs.filter((cve) => cve.title.toLowerCase().includes(lowerQuery))
    }

    setSearchResults(results)
    setShowResults(true)
  }

  const handleResultClick = (cveId: string) => {
    setSearchQuery(cveId)
    setShowResults(false)
    router.push(`/cve/${cveId}`)
  }

  return (
    <div className="space-y-4 relative">
      {/* Mode buttons */}
      <div className="flex gap-2">
        <Button variant={mode === "cve" ? "default" : "outline"} onClick={() => setMode("cve")} size="sm">
          CVE
        </Button>
        <Button variant={mode === "keyword" ? "default" : "outline"} onClick={() => setMode("keyword")} size="sm">
          키워드
        </Button>
      </div>

      {/* Search input */}
      <div className="relative">
        <div className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground z-10">
          {mode === "cve" ? <Tag className="h-5 w-5" /> : <Search className="h-5 w-5" />}
        </div>
        <Input
          type="text"
          placeholder={mode === "cve" ? "CVE-2025-12345 또는 년도 입력 (예: 2025)" : "키워드를 입력"}
          className="pl-10 h-12 text-base bg-card"
          value={searchQuery}
          onChange={(e) => handleSearch(e.target.value)}
          onFocus={() => searchQuery && setShowResults(true)}
        />

        {showResults && searchResults.length > 0 && (
          <Card className="absolute top-full left-0 right-0 mt-2 z-20 bg-card border-border max-h-64 overflow-y-auto">
            <div className="divide-y divide-border">
              {searchResults.map((cve) => (
                <div
                  key={cve.id}
                  className="p-3 hover:bg-secondary cursor-pointer transition-colors"
                  onClick={() => handleResultClick(cve.id)}
                >
                  <div className="font-mono text-sm font-semibold text-primary">{cve.id}</div>
                  <div className="text-xs text-muted-foreground mt-1">{cve.title}</div>
                </div>
              ))}
            </div>
          </Card>
        )}

        {showResults && searchResults.length === 0 && searchQuery && (
          <Card className="absolute top-full left-0 right-0 mt-2 z-20 bg-card border-border p-3">
            <div className="text-sm text-muted-foreground text-center">검색 결과가 없습니다</div>
          </Card>
        )}
      </div>
    </div>
  )
}
