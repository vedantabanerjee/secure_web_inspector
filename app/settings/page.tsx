'use client'

import { useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Textarea } from '@/components/ui/textarea'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { SettingsIcon, ArrowLeft, Shield, Bell, Database, Key, Globe, Save, AlertTriangle, Info } from 'lucide-react'
import Link from 'next/link'

export default function SettingsPage() {
  const [settings, setSettings] = useState({
    // General Settings
    organizationName: 'SecureWeb Inspector',
    defaultScanTimeout: '300',
    maxConcurrentScans: '5',
    
    // Security Settings
    enableRateLimiting: true,
    maxRequestsPerMinute: '100',
    enableLogging: true,
    logRetentionDays: '90',
    
    // Notification Settings
    emailNotifications: true,
    slackNotifications: false,
    webhookUrl: '',
    notificationEmail: 'admin@company.com',
    
    // Scanning Settings
    defaultPortRange: '1-1000',
    enableSSLVerification: true,
    userAgent: 'SecureWeb Inspector v1.0',
    requestTimeout: '30',
    
    // Integration Settings
    owaspZapApiKey: '',
    burpSuiteApiUrl: '',
    jiraIntegration: false,
    jiraUrl: '',
    jiraApiKey: ''
  })

  const handleSettingChange = (key: string, value: any) => {
    setSettings(prev => ({ ...prev, [key]: value }))
  }

  const handleSave = () => {
    // Simulate saving settings
    console.log('Saving settings:', settings)
    // In a real app, this would make an API call
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center space-x-3">
              <Link href="/">
                <Button variant="ghost" size="sm">
                  <ArrowLeft className="h-4 w-4 mr-2" />
                  Back to Dashboard
                </Button>
              </Link>
              <SettingsIcon className="h-8 w-8 text-blue-600" />
              <h1 className="text-2xl font-bold text-gray-900">Settings</h1>
            </div>
            <Button onClick={handleSave}>
              <Save className="h-4 w-4 mr-2" />
              Save Changes
            </Button>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <Tabs defaultValue="general" className="w-full">
          <TabsList className="grid w-full grid-cols-5">
            <TabsTrigger value="general">General</TabsTrigger>
            <TabsTrigger value="security">Security</TabsTrigger>
            <TabsTrigger value="scanning">Scanning</TabsTrigger>
            <TabsTrigger value="notifications">Notifications</TabsTrigger>
            <TabsTrigger value="integrations">Integrations</TabsTrigger>
          </TabsList>

          <TabsContent value="general" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>General Settings</CardTitle>
                <CardDescription>
                  Configure basic application settings and preferences
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div>
                    <Label htmlFor="org-name">Organization Name</Label>
                    <Input
                      id="org-name"
                      value={settings.organizationName}
                      onChange={(e) => handleSettingChange('organizationName', e.target.value)}
                      className="mt-1"
                    />
                  </div>
                  
                  <div>
                    <Label htmlFor="scan-timeout">Default Scan Timeout (seconds)</Label>
                    <Input
                      id="scan-timeout"
                      type="number"
                      value={settings.defaultScanTimeout}
                      onChange={(e) => handleSettingChange('defaultScanTimeout', e.target.value)}
                      className="mt-1"
                    />
                  </div>
                  
                  <div>
                    <Label htmlFor="max-scans">Max Concurrent Scans</Label>
                    <Input
                      id="max-scans"
                      type="number"
                      value={settings.maxConcurrentScans}
                      onChange={(e) => handleSettingChange('maxConcurrentScans', e.target.value)}
                      className="mt-1"
                    />
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="security" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Shield className="h-5 w-5" />
                  <span>Security Configuration</span>
                </CardTitle>
                <CardDescription>
                  Configure security-related settings and access controls
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="flex items-center justify-between">
                  <div>
                    <Label htmlFor="rate-limiting">Enable Rate Limiting</Label>
                    <p className="text-sm text-gray-600">Protect against abuse and DoS attacks</p>
                  </div>
                  <Switch
                    id="rate-limiting"
                    checked={settings.enableRateLimiting}
                    onCheckedChange={(checked) => handleSettingChange('enableRateLimiting', checked)}
                  />
                </div>
                
                {settings.enableRateLimiting && (
                  <div>
                    <Label htmlFor="max-requests">Max Requests Per Minute</Label>
                    <Input
                      id="max-requests"
                      type="number"
                      value={settings.maxRequestsPerMinute}
                      onChange={(e) => handleSettingChange('maxRequestsPerMinute', e.target.value)}
                      className="mt-1"
                    />
                  </div>
                )}
                
                <div className="flex items-center justify-between">
                  <div>
                    <Label htmlFor="logging">Enable Security Logging</Label>
                    <p className="text-sm text-gray-600">Log all security-related events</p>
                  </div>
                  <Switch
                    id="logging"
                    checked={settings.enableLogging}
                    onCheckedChange={(checked) => handleSettingChange('enableLogging', checked)}
                  />
                </div>
                
                {settings.enableLogging && (
                  <div>
                    <Label htmlFor="log-retention">Log Retention Period (days)</Label>
                    <Input
                      id="log-retention"
                      type="number"
                      value={settings.logRetentionDays}
                      onChange={(e) => handleSettingChange('logRetentionDays', e.target.value)}
                      className="mt-1"
                    />
                  </div>
                )}
                
                <Alert>
                  <AlertTriangle className="h-4 w-4" />
                  <AlertDescription>
                    Security settings changes will take effect immediately. Ensure you understand 
                    the implications before modifying these settings.
                  </AlertDescription>
                </Alert>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="scanning" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Globe className="h-5 w-5" />
                  <span>Scanning Configuration</span>
                </CardTitle>
                <CardDescription>
                  Configure default scanning parameters and behavior
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div>
                    <Label htmlFor="port-range">Default Port Range</Label>
                    <Input
                      id="port-range"
                      value={settings.defaultPortRange}
                      onChange={(e) => handleSettingChange('defaultPortRange', e.target.value)}
                      className="mt-1"
                      placeholder="1-1000"
                    />
                  </div>
                  
                  <div>
                    <Label htmlFor="request-timeout">Request Timeout (seconds)</Label>
                    <Input
                      id="request-timeout"
                      type="number"
                      value={settings.requestTimeout}
                      onChange={(e) => handleSettingChange('requestTimeout', e.target.value)}
                      className="mt-1"
                    />
                  </div>
                </div>
                
                <div>
                  <Label htmlFor="user-agent">User Agent String</Label>
                  <Input
                    id="user-agent"
                    value={settings.userAgent}
                    onChange={(e) => handleSettingChange('userAgent', e.target.value)}
                    className="mt-1"
                  />
                </div>
                
                <div className="flex items-center justify-between">
                  <div>
                    <Label htmlFor="ssl-verification">Enable SSL Certificate Verification</Label>
                    <p className="text-sm text-gray-600">Verify SSL certificates during scans</p>
                  </div>
                  <Switch
                    id="ssl-verification"
                    checked={settings.enableSSLVerification}
                    onCheckedChange={(checked) => handleSettingChange('enableSSLVerification', checked)}
                  />
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="notifications" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Bell className="h-5 w-5" />
                  <span>Notification Settings</span>
                </CardTitle>
                <CardDescription>
                  Configure how and when you receive notifications about scan results
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="flex items-center justify-between">
                  <div>
                    <Label htmlFor="email-notifications">Email Notifications</Label>
                    <p className="text-sm text-gray-600">Receive scan results via email</p>
                  </div>
                  <Switch
                    id="email-notifications"
                    checked={settings.emailNotifications}
                    onCheckedChange={(checked) => handleSettingChange('emailNotifications', checked)}
                  />
                </div>
                
                {settings.emailNotifications && (
                  <div>
                    <Label htmlFor="notification-email">Notification Email</Label>
                    <Input
                      id="notification-email"
                      type="email"
                      value={settings.notificationEmail}
                      onChange={(e) => handleSettingChange('notificationEmail', e.target.value)}
                      className="mt-1"
                    />
                  </div>
                )}
                
                <div className="flex items-center justify-between">
                  <div>
                    <Label htmlFor="slack-notifications">Slack Notifications</Label>
                    <p className="text-sm text-gray-600">Send notifications to Slack channel</p>
                  </div>
                  <Switch
                    id="slack-notifications"
                    checked={settings.slackNotifications}
                    onCheckedChange={(checked) => handleSettingChange('slackNotifications', checked)}
                  />
                </div>
                
                {settings.slackNotifications && (
                  <div>
                    <Label htmlFor="webhook-url">Slack Webhook URL</Label>
                    <Input
                      id="webhook-url"
                      value={settings.webhookUrl}
                      onChange={(e) => handleSettingChange('webhookUrl', e.target.value)}
                      className="mt-1"
                      placeholder="https://hooks.slack.com/services/..."
                    />
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="integrations" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Database className="h-5 w-5" />
                  <span>External Integrations</span>
                </CardTitle>
                <CardDescription>
                  Configure integrations with external security tools and services
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div>
                  <Label htmlFor="owasp-zap-key">OWASP ZAP API Key</Label>
                  <Input
                    id="owasp-zap-key"
                    type="password"
                    value={settings.owaspZapApiKey}
                    onChange={(e) => handleSettingChange('owaspZapApiKey', e.target.value)}
                    className="mt-1"
                    placeholder="Enter OWASP ZAP API key"
                  />
                </div>
                
                <div>
                  <Label htmlFor="burp-suite-url">Burp Suite API URL</Label>
                  <Input
                    id="burp-suite-url"
                    value={settings.burpSuiteApiUrl}
                    onChange={(e) => handleSettingChange('burpSuiteApiUrl', e.target.value)}
                    className="mt-1"
                    placeholder="http://localhost:1337"
                  />
                </div>
                
                <div className="border-t pt-6">
                  <div className="flex items-center justify-between mb-4">
                    <div>
                      <Label htmlFor="jira-integration">JIRA Integration</Label>
                      <p className="text-sm text-gray-600">Automatically create tickets for vulnerabilities</p>
                    </div>
                    <Switch
                      id="jira-integration"
                      checked={settings.jiraIntegration}
                      onCheckedChange={(checked) => handleSettingChange('jiraIntegration', checked)}
                    />
                  </div>
                  
                  {settings.jiraIntegration && (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div>
                        <Label htmlFor="jira-url">JIRA URL</Label>
                        <Input
                          id="jira-url"
                          value={settings.jiraUrl}
                          onChange={(e) => handleSettingChange('jiraUrl', e.target.value)}
                          className="mt-1"
                          placeholder="https://company.atlassian.net"
                        />
                      </div>
                      
                      <div>
                        <Label htmlFor="jira-api-key">JIRA API Key</Label>
                        <Input
                          id="jira-api-key"
                          type="password"
                          value={settings.jiraApiKey}
                          onChange={(e) => handleSettingChange('jiraApiKey', e.target.value)}
                          className="mt-1"
                          placeholder="Enter JIRA API key"
                        />
                      </div>
                    </div>
                  )}
                </div>
                
                <Alert>
                  <Info className="h-4 w-4" />
                  <AlertDescription>
                    API keys and sensitive information are encrypted and stored securely. 
                    Test your integrations after configuration to ensure they work correctly.
                  </AlertDescription>
                </Alert>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  )
}
