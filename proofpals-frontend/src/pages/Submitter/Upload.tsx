// src/pages/Submitter/Upload.tsx
import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Upload, FileText, CheckCircle2, AlertCircle } from 'lucide-react';
import { apiClient } from '@/lib/api/client';
import { API_ENDPOINTS } from '@/lib/api/endpoints';
import { useNavigate } from 'react-router-dom';
import { useAuthStore } from '@/store/authStore';
import { useCryptoStore } from '@/lib/crypto/key-manager';
import { Header } from '@/components/common/Header';
import { Navigation } from '@/components/common/Navigation';
import { toast } from 'sonner';

const submissionSchema = z.object({
  genre: z.string().min(1, 'Please select a genre'),
  contentRef: z.string().url('Please enter a valid URL').or(z.string().min(1)),
  consentIpMac: z.boolean().refine((val) => val === true, {
    message: 'You must consent to IP/MAC storage for escalation purposes',
  }),
});

type SubmissionFormData = z.infer<typeof submissionSchema>;

const GENRES = [
  { value: 'news', label: 'News & Journalism' },
  { value: 'research', label: 'Research & Academia' },
  { value: 'music', label: 'Music & Audio' },
  { value: 'video', label: 'Video & Film' },
  { value: 'literature', label: 'Literature & Writing' },
  { value: 'art', label: 'Art & Visual Media' },
];

export function UploadPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { user } = useAuthStore();
  const { getPublicKeyHex } = useCryptoStore();
  const publicKeyHex = getPublicKeyHex();
  const [file, setFile] = useState<File | null>(null);

  const {
    register,
    handleSubmit,
    formState: { errors },
    setValue,
    watch,
  } = useForm<SubmissionFormData>({
    resolver: zodResolver(submissionSchema),
  });

  const submitMutation = useMutation({
    mutationFn: async (data: SubmissionFormData) => {
      // In production, upload file to S3 or similar first
      return apiClient.post(API_ENDPOINTS.submissions, {
        genre: data.genre,
        content_ref: data.contentRef,
        submitter_ip: null, // Let backend capture
        submitter_mac: null, // Optional
      });
    },
    onSuccess: (data: any) => {
      const submissionId = data.submission_id;
      toast.success(`Submission created successfully! ID: ${submissionId}`);
      
      // Invalidate queries to update all dashboards
      queryClient.invalidateQueries({ queryKey: ['my-submissions'] });
      queryClient.invalidateQueries({ queryKey: ['admin-submissions'] });
      queryClient.invalidateQueries({ queryKey: ['reviewer-stats'] });
      
      const role = user?.role;
      if (role === 'reviewer') {
        navigate(`/review/${submissionId}`);
      } else {
        navigate('/submitter/my-submissions');
      }
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.error || 'Failed to submit');
    },
  });

  const onSubmit = (data: SubmissionFormData) => {
    submitMutation.mutate(data);
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0];
    if (selectedFile) {
      // Validate file size (e.g., max 50MB)
      if (selectedFile.size > 50 * 1024 * 1024) {
        toast.error('File size must be less than 50MB');
        return;
      }
      setFile(selectedFile);
      // Demo/dev strategy to allow reviewer preview while respecting backend 500-char limit
      const MAX_REF_LEN = 480; // stay below DB limit (500)

      const setClamped = (value: string) => {
        const clamped = value.length > MAX_REF_LEN ? value.slice(0, MAX_REF_LEN - 15) + '…[truncated]' : value;
        setValue('contentRef', clamped, { shouldValidate: true, shouldDirty: true });
      };

      const reader = new FileReader();
      reader.onload = () => {
        const result = reader.result as string;

        if (selectedFile.type.startsWith('text/')) {
          // If we read as text, result is the text content
          const textContent = typeof result === 'string' ? result : '';
          if (!textContent) {
            setClamped(`file://${selectedFile.name}`);
            return;
          }
          setClamped(textContent);
          return;
        }

        // Otherwise use data URL for images/PDFs, clamp to fit DB column
        if (typeof result === 'string' && result.startsWith('data:')) {
          setClamped(result);
        } else {
          setClamped(`file://${selectedFile.name}`);
        }
      };

      // Use text for text/*, otherwise data URL
      if (selectedFile.type.startsWith('text/')) {
        reader.readAsText(selectedFile);
      } else {
        reader.readAsDataURL(selectedFile);
      }
    }
  };

  return (
    <div className="flex min-h-screen">
      <Navigation role={user?.role as 'admin' | 'reviewer' | 'submitter'} />
      <div className="flex-1">
        <Header />
        <main className="container mx-auto max-w-3xl space-y-8 p-6">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-4xl font-light text-gray-900 mb-2">Submit Content</h1>
        <p className="text-gray-500">Submit your work for anonymous peer review</p>
      </div>

      {/* Privacy Notice */}
      <Alert className="border-blue-200 bg-blue-50">
        <AlertCircle className="h-4 w-4 text-blue-600" />
        <AlertDescription className="text-blue-900">
          Your submission will be reviewed anonymously. Your identity is protected 
          unless the content is flagged for legal review.
        </AlertDescription>
      </Alert>

      {/* Upload Form */}
      <form onSubmit={handleSubmit(onSubmit)}>
        <Card>
          <CardHeader>
            <CardTitle>Submission Details</CardTitle>
            <CardDescription>
              Provide information about your content
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {/* Genre Selection */}
            <div className="space-y-2">
              <Label htmlFor="genre">Genre / Category *</Label>
              <Select
                value={watch('genre')}
                onValueChange={(value: string) => setValue('genre', value, { shouldValidate: true, shouldDirty: true })}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select a genre" />
                </SelectTrigger>
                <SelectContent>
                  {GENRES.map((genre) => (
                    <SelectItem key={genre.value} value={genre.value}>
                      {genre.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {errors.genre && (
                <p className="text-sm text-red-600">{errors.genre.message}</p>
              )}
            </div>

            {/* File Upload */}
            <div className="space-y-2">
              <Label htmlFor="file">Upload File (Optional)</Label>
              <div className="flex items-center gap-4">
                <Input
                  id="file"
                  type="file"
                  accept=".pdf,.epub,.txt,.docx"
                  onChange={handleFileChange}
                  className="flex-1"
                />
                {file && (
                  <div className="flex items-center gap-2 text-sm text-green-600">
                    <CheckCircle2 className="h-4 w-4" />
                    {file.name}
                  </div>
                )}
              </div>
              <p className="text-xs text-muted-foreground">
                Supported formats: PDF, EPUB, TXT, DOCX (max 50MB)
              </p>
            </div>

            {/* OR Content URL */}
            <div className="space-y-2">
              <Label htmlFor="contentRef">Or Content URL *</Label>
              <Input
                id="contentRef"
                placeholder="https://example.com/article"
                {...register('contentRef')}
                disabled={!!file}
              />
              {errors.contentRef && (
                <p className="text-sm text-red-600">{errors.contentRef.message}</p>
              )}
              <p className="text-xs text-muted-foreground">
                Provide a link to your content (if not uploading a file)
              </p>
            </div>

            {/* Consent Checkbox */}
            <div className="space-y-4 rounded-lg border bg-muted/50 p-4">
              <div className="flex items-start gap-3">
                <Checkbox
                  id="consent"
                  onCheckedChange={(checked: boolean | undefined) => 
                    setValue('consentIpMac', checked as boolean)
                  }
                />
                <div className="space-y-1">
                  <Label htmlFor="consent" className="cursor-pointer font-normal">
                    I consent to IP/MAC address storage for legal escalation purposes
                  </Label>
                  <p className="text-xs text-muted-foreground">
                    Your IP and MAC addresses will be hashed and stored only for use 
                    in legal escalation scenarios. They will not be used for tracking 
                    or linked to your identity under normal circumstances.
                  </p>
                </div>
              </div>
              {errors.consentIpMac && (
                <p className="text-sm text-red-600">{errors.consentIpMac.message}</p>
              )}
            </div>

            {/* Submit Button */}
            <Button
              type="submit"
              size="lg"
              className="w-full"
              disabled={submitMutation.isPending}
            >
              {submitMutation.isPending ? (
                <>
                  <Upload className="mr-2 h-4 w-4 animate-pulse" />
                  Submitting...
                </>
              ) : (
                <>
                  <FileText className="mr-2 h-4 w-4" />
                  Submit for Review
                </>
              )}
            </Button>
          </CardContent>
        </Card>
      </form>

      {/* Subtle Public Key Display */}
      {publicKeyHex && (
        <div className="mt-8 pt-4 border-t border-gray-100">
          <div className="text-xs text-gray-400 space-y-1">
            <div className="flex items-center justify-between">
              <span>Submitter ID:</span>
              <span className="font-mono">{publicKeyHex.substring(0, 8)}...{publicKeyHex.substring(-8)}</span>
            </div>
          </div>
        </div>
      )}
        </main>
      </div>
    </div>
  );
}