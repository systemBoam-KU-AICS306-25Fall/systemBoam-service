"use client"

import { useState, KeyboardEvent } from "react"
import { useRouter } from "next/navigation"
import { Search, Tag } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card } from "@/components/ui/card"
import { apiGet } from "@/lib/api"

type SearchMode = "cve" | "keyword"

type SearchResult = {
  cve: string
  summary: string
  link: string
}

type SearchResponse = {
  results: SearchResult[]
}

export function SearchSection() {
  const router = useRouter()
  const [mode, setMode] = useState<SearchMode>("cve")
  const [searchQuery, setSearchQuery] = useState("")
  const [searchResults, setSearchResults] = useState<SearchResult[]>([])
  const [showResults, setShowResults] = useState(false)

  const handleSearch = async (query: string) => {
    setSearchQuery(query)

    if (!query.trim()) {
      setSearchResults([])
      setShowResults(false)
      return
    }

    try {
      // 백엔드 검색 API 호출
      // mode === "cve" → type=cve, mode === "keyword" → type=keyword
      const resp = await apiGet<SearchResponse>(
        `/api/v1/search?q=${encodeURIComponent(query)}&type=${mode}`
      )

      setSearchResults(resp.results ?? [])
      setShowResults(true)
    } catch (e) {
      // 에러 시 결과 창만 “없음”으로 표시
      setSearchResults([])
      setShowResults(true)
    }
  }

  const handleResultClick = (cveId: string) => {
    setSearchQuery(cveId)
    setShowResults(false)
    router.push(`/cve/${cveId}`)
  }

  const handleKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key !== "Enter") return
    const q = searchQuery.trim()
    if (!q) return

    setShowResults(false)

    if (mode === "cve") {
      // 입력한 값을 그대로 CVE ID로 사용해 상세 페이지로 이동
      router.push(`/cve/${q}`)
    } else {
      // 키워드 모드: (검색 페이지가 있다면) 쿼리 파라미터로 전달
      router.push(`/search?query=${encodeURIComponent(q)}`)
    }
  }

  return (
    <div className="space-y-4 relative">
      {/* Mode buttons */}
      <div className="flex gap-2">
        <Button
          variant={mode === "cve" ? "default" : "outline"}
          onClick={() => setMode("cve")}
          size="sm"
        >
          CVE
        </Button>
        <Button
          variant={mode === "keyword" ? "default" : "outline"}
          onClick={() => setMode("keyword")}
          size="sm"
        >
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
          placeholder={
            mode === "cve"
              ? "CVE-2025-12345 또는 년도 입력 (예: 2025)"
              : "키워드를 입력"
          }
          className="pl-10 h-12 text-base bg-card"
          value={searchQuery}
          onChange={(e) => {
            // UI는 그대로 유지, 입력 변경 시마다 백엔드 검색
            void handleSearch(e.target.value)
          }}
          onFocus={() => searchQuery && setShowResults(true)}
          onKeyDown={handleKeyDown}
        />

        {showResults && searchResults.length > 0 && (
          <Card className="absolute top-full left-0 right-0 mt-2 z-20 bg-card border-border max-h-64 overflow-y-auto">
            <div className="divide-y divide-border">
              {searchResults.map((item) => (
                <div
                  key={item.cve}
                  className="p-3 hover:bg-secondary cursor-pointer transition-colors"
                  onClick={() => handleResultClick(item.cve)}
                >
                  <div className="font-mono text-sm font-semibold text-primary">
                    {item.cve}
                  </div>
                  <div className="text-xs text-muted-foreground mt-1">
                    {item.summary || "(no summary)"}
                  </div>
                </div>
              ))}
            </div>
          </Card>
        )}

        {showResults && searchResults.length === 0 && searchQuery && (
          <Card className="absolute top-full left-0 right-0 mt-2 z-20 bg-card border-border p-3">
            <div className="text-sm text-muted-foreground text-center">
              검색 결과가 없습니다
            </div>
          </Card>
        )}
      </div>
    </div>
  )
}
