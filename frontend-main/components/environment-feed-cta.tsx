"use client"

import type React from "react"

import { Card, CardContent } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Shield, ChevronRight } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { useRef, useState } from "react"

const previewExamples = [
  { cve: "CVE-2025-0001", product: "Apache Log4j 2.14.1" },
  { cve: "CVE-2025-0003", product: "Windows Server 2019" },
  { cve: "CVE-2025-0007", product: "OpenSSL 1.1.1k" },
]

export function EnvironmentFeedCTA() {
  const fileInputRef = useRef<HTMLInputElement>(null)
  const [uploadedFile, setUploadedFile] = useState<File | null>(null)

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) {
      setUploadedFile(file)
      console.log("[v0] File uploaded:", file.name, file.size)
    }
  }

  const handleScanClick = () => {
    fileInputRef.current?.click()
  }

  return (
    <Card className="bg-gradient-to-br from-primary/10 to-primary/5 border-primary/20 bg-zinc-900">
      <CardContent className="p-8">
        <div className="flex flex-col items-center gap-6">
          <div className="w-full space-y-4">
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 rounded-full bg-primary/20 flex items-center justify-center flex-shrink-0">
                <Shield className="h-6 w-6 text-primary" />
              </div>
              <h2 className="font-bold text-foreground text-3xl">내 환경별 취약점 피드</h2>
            </div>
            <p className="text-muted-foreground leading-relaxed">
              제품/버전 정보를 등록하면, 당신의 환경에 영향을 주는 CVE를 우선순위로 제공합니다.
            </p>
          </div>

          {/* Preview examples */}
          <div className="w-full space-y-2">
            <p className="text-sm font-medium text-muted-foreground">미리보기:</p>
            <div className="flex flex-wrap gap-3 justify-center">
              {previewExamples.map((example) => (
                <div
                  key={example.cve}
                  className="flex items-center gap-2 px-3 py-2 rounded-lg border border-border bg-gray-700"
                >
                  <Badge variant="outline" className="text-xs bg-muted">
                    {example.cve}
                  </Badge>
                  <span className="text-sm text-secondary-foreground">{example.product}</span>
                </div>
              ))}
            </div>
          </div>

          {uploadedFile && <div className="text-sm text-primary font-medium">✓ {uploadedFile.name}</div>}

          <input
            ref={fileInputRef}
            type="file"
            onChange={handleFileSelect}
            className="hidden"
            accept=".json,.xml,.csv,.txt"
          />

          <Button onClick={handleScanClick} size="lg" className="gap-2 w-full sm:w-auto justify-center">
            지금 내 환경 스캔
            <ChevronRight className="h-4 w-4" />
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}
