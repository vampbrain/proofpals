// src/pages/Admin/RingManagement.tsx
import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Header } from '@/components/common/Header';
import { Navigation } from '@/components/common/Navigation';
import { Loading } from '@/components/common/Loading';
import { PlusCircle, Trash2, Edit, UserPlus, UserMinus, ToggleLeft, ToggleRight } from 'lucide-react';
import { apiClient } from '@/lib/api/client';
import { toast } from 'sonner';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';

const ringSchema = z.object({
  genre: z.string().min(1, 'Genre is required'),
  epoch: z.string().min(1, 'Epoch is required'),
  pubkeys: z.string()
    .min(1, 'At least one public key is required')
    .transform((val) => val.split(/\r?\n/).map((s) => s.trim()).filter(Boolean))
    .refine((arr) => arr.length > 0, 'At least one public key is required'),
});

type RingFormData = z.infer<typeof ringSchema>;

const GENRES = [
  { value: 'news', label: 'News & Journalism' },
  { value: 'research', label: 'Research & Academia' },
  { value: 'music', label: 'Music & Audio' },
  { value: 'video', label: 'Video & Film' },
  { value: 'literature', label: 'Literature & Writing' },
  { value: 'art', label: 'Art & Visual Media' },
];

export function RingManagement() {
  const queryClient = useQueryClient();
  const [isCreating, setIsCreating] = useState(false);
  const [editingRing, setEditingRing] = useState<any>(null);
  const [addingMember, setAddingMember] = useState<any>(null);
  const [newMemberKey, setNewMemberKey] = useState('');

  const {
    register,
    handleSubmit,
    reset,
    setValue,
    watch,
    formState: { errors },
  } = useForm<RingFormData>({
    resolver: zodResolver(ringSchema),
    defaultValues: {
      genre: '',
      epoch: '',
      pubkeys: '' as unknown as string[],
    },
  });

  const selectedGenre = watch('genre');

  const { data: ringsResponse, isLoading } = useQuery<any>({
    queryKey: ['rings'],
    queryFn: () => apiClient.get('/api/v1/rings'),
  });

  const rings = ringsResponse?.rings || [];

  const { data: availableKeysResponse, error: keysError, isLoading: keysLoading } = useQuery({
    queryKey: ['available-public-keys'],
    queryFn: async () => {
      console.log('🔍 Fetching available public keys...');
      const result = await apiClient.get('/api/v1/admin/available-public-keys') as {
        success: boolean;
        available_keys: Array<{
          user_id: number;
          username: string;
          role: string;
          public_key_hex: string;
        }>;
        total_count: number;
      };
      console.log('✅ Available public keys response:', result);
      return result;
    },
    retry: 3,
    staleTime: 30000, // 30 seconds
  });

  const availablePubKeys = availableKeysResponse?.available_keys || [];

  const { data: ringDetails } = useQuery<{ pubkeys: string[]; [key: string]: any }>({
    queryKey: ['ring-details', editingRing?.id],
    queryFn: () => apiClient.get(`/api/v1/rings/${editingRing.id}`),
    enabled: !!editingRing,
  });

  const createRingMutation = useMutation({
    mutationFn: (data: RingFormData) => {
      return apiClient.post('/api/v1/rings', {
        genre: data.genre,
        epoch: parseInt(data.epoch, 10),
        pubkeys: (data as any).pubkeys,
      });
    },
    onSuccess: () => {
      toast.success('Ring created successfully!');
      reset();
      setIsCreating(false);
      queryClient.invalidateQueries({ queryKey: ['rings'] });
    },
    onError: (error: any) => {
      toast.error(error.message || 'Failed to create ring');
    },
  });

  const deleteRingMutation = useMutation({
    mutationFn: (ringId: number) => apiClient.delete(`/api/v1/rings/${ringId}`),
    onSuccess: () => {
      toast.success('Ring deleted successfully!');
      queryClient.invalidateQueries({ queryKey: ['rings'] });
    },
    onError: (error: any) => {
      console.error('Delete ring error:', error);
      const errorMessage = error.response?.data?.detail || error.message || 'Failed to delete ring';
      toast.error(`Delete failed: ${errorMessage}`);
    },
  });

  const toggleRingStatusMutation = useMutation({
    mutationFn: ({ ringId, active }: { ringId: number; active: boolean }) => 
      apiClient.put(`/api/v1/rings/${ringId}`, { active }),
    onSuccess: () => {
      toast.success('Ring status updated successfully!');
      queryClient.invalidateQueries({ queryKey: ['rings'] });
    },
    onError: (error: any) => {
      toast.error(error.message || 'Failed to update ring status');
    },
  });

  const addMemberMutation = useMutation({
    mutationFn: ({ ringId, publicKey }: { ringId: number; publicKey: string }) => 
      apiClient.post(`/api/v1/rings/${ringId}/members`, { public_key_hex: publicKey }),
    onSuccess: (_, { ringId }) => {
      toast.success('Member added successfully!');
      setAddingMember(null);
      setNewMemberKey('');
      queryClient.invalidateQueries({ queryKey: ['rings'] });
      queryClient.invalidateQueries({ queryKey: ['ring-details', ringId] });
    },
    onError: (error: any) => {
      toast.error(error.message || 'Failed to add member');
    },
  });

  const removeMemberMutation = useMutation({
    mutationFn: ({ ringId, publicKey }: { ringId: number; publicKey: string }) => 
      apiClient.delete(`/api/v1/rings/${ringId}/members/${publicKey}`),
    onSuccess: (_, { ringId }) => {
      toast.success('Member removed successfully!');
      queryClient.invalidateQueries({ queryKey: ['rings'] });
      queryClient.invalidateQueries({ queryKey: ['ring-details', ringId] });
    },
    onError: (error: any) => {
      toast.error(error.message || 'Failed to remove member');
    },
  });

  const onSubmit = (data: RingFormData) => {
    createRingMutation.mutate(data);
  };

  if (isLoading) return <Loading />;

  return (
    <div className="flex min-h-screen">
      <Navigation role="admin" />
      <div className="flex-1">
        <Header />
        <main className="container mx-auto p-6">
          <h1 className="mb-6 text-3xl font-bold">Ring Management</h1>
          
          <div className="mb-8">
            <Card>
              <CardHeader>
                <CardTitle>Create New Ring</CardTitle>
                <CardDescription>
                  Create a new ring for a specific genre and epoch
                </CardDescription>
              </CardHeader>
              <CardContent>
                {isCreating ? (
                  <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
                    <div className="grid gap-4 md:grid-cols-2">
                      <div className="space-y-2">
                        <Label htmlFor="genre">Genre</Label>
                        <Select 
                          value={selectedGenre || undefined}
                          onValueChange={(value) => setValue('genre', value, { shouldValidate: true, shouldDirty: true })}
                        >
                          <SelectTrigger>
                            <SelectValue placeholder="Select genre" />
                          </SelectTrigger>
                          <SelectContent>
                            {GENRES.map((genre) => (
                              <SelectItem key={genre.value} value={genre.value}>
                                {genre.label}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                        <input type="hidden" {...register('genre')} />
                        {errors.genre && (
                          <p className="text-sm text-red-600">{errors.genre.message}</p>
                        )}
                      </div>
                      
                      <div className="space-y-2">
                        <Label htmlFor="epoch">Epoch</Label>
                        <Input
                          id="epoch"
                          placeholder="e.g., 2023-Q1"
                          {...register('epoch')}
                        />
                        {errors.epoch && (
                          <p className="text-sm text-red-600">{errors.epoch.message}</p>
                        )}
                      </div>
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="pubkeys">Ring Public Keys (one per line, hex)</Label>
                      <textarea
                        id="pubkeys"
                        className="w-full min-h-[160px] rounded-md border px-3 py-2 text-sm"
                        placeholder="abcdef...\n012345..."
                        {...register('pubkeys' as any)}
                      />
                      {(errors as any).pubkeys && (
                        <p className="text-sm text-red-600">{(errors as any).pubkeys.message as any}</p>
                      )}
                      
                      {/* Available Public Keys Section - Always Show */}
                      <div className="mt-3 rounded border bg-muted/30 p-3 text-xs">
                        <div className="mb-2 font-medium">Available Public Keys (click to add)</div>
                        {availablePubKeys && availablePubKeys.length > 0 ? (
                          <div className="grid gap-2 md:grid-cols-2">
                            {availablePubKeys.map((pk) => (
                              <button
                                key={pk.user_id + pk.public_key_hex}
                                type="button"
                                className="p-2 rounded border bg-white text-left hover:bg-muted transition-colors"
                                onClick={() => {
                                  const current = (document.getElementById('pubkeys') as HTMLTextAreaElement);
                                  const toAdd = pk.public_key_hex;
                                  if (current) {
                                    const existing = current.value.trim();
                                    current.value = existing ? existing + "\n" + toAdd : toAdd;
                                    setValue('pubkeys' as any, current.value);
                                  }
                                }}
                                title={`${pk.username} (${pk.role}): ${pk.public_key_hex}`}
                              >
                                <div className="flex items-center justify-between mb-1">
                                  <span className="font-medium text-gray-900">{pk.username}</span>
                                  <span className="text-xs text-gray-500 capitalize px-2 py-1 bg-gray-100 rounded">{pk.role}</span>
                                </div>
                                <div className="text-gray-600 truncate text-xs">{pk.public_key_hex}</div>
                              </button>
                            ))}
                          </div>
                        ) : (
                          <div className="text-gray-500 text-center py-4">
                            {keysLoading ? (
                              <div className="flex items-center justify-center gap-2">
                                <div className="w-4 h-4 border-2 border-gray-300 border-t-gray-600 rounded-full animate-spin"></div>
                                Loading available public keys...
                              </div>
                            ) : keysError ? (
                              <div className="text-red-500">
                                <p>Failed to load public keys</p>
                                <p className="text-xs mt-1">Please check if you have admin permissions</p>
                              </div>
                            ) : (
                              <div>
                                <p>No public keys available yet.</p>
                                <p className="text-xs mt-1">Users need to generate keys first.</p>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    </div>
                    
                    <div className="flex justify-end space-x-2">
                      <Button
                        type="button"
                        variant="outline"
                        onClick={() => {
                          reset();
                          setIsCreating(false);
                        }}
                      >
                        Cancel
                      </Button>
                      <Button
                        type="submit"
                        disabled={createRingMutation.isPending}
                      >
                        {createRingMutation.isPending ? 'Creating...' : 'Create Ring'}
                      </Button>
                    </div>
                  </form>
                ) : (
                  <Button
                    onClick={() => setIsCreating(true)}
                    className="w-full"
                  >
                    <PlusCircle className="mr-2 h-4 w-4" />
                    Create New Ring
                  </Button>
                )}
              </CardContent>
            </Card>
          </div>
          
          <Card>
            <CardHeader>
              <CardTitle>Active Rings</CardTitle>
              <CardDescription>
                Manage existing rings for different genres and epochs
              </CardDescription>
            </CardHeader>
            <CardContent>
              {rings && rings.length > 0 ? (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>ID</TableHead>
                      <TableHead>Genre</TableHead>
                      <TableHead>Epoch</TableHead>
                      <TableHead>Members</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Created</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {rings.map((ring: any) => (
                      <TableRow key={ring.id}>
                        <TableCell>{ring.id}</TableCell>
                        <TableCell className="capitalize">{ring.genre}</TableCell>
                        <TableCell>{ring.epoch}</TableCell>
                        <TableCell>{ring.member_count}</TableCell>
                        <TableCell>
                          <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${
                            ring.active 
                              ? 'bg-green-100 text-green-800' 
                              : 'bg-gray-100 text-gray-800'
                          }`}>
                            {ring.active ? 'Active' : 'Inactive'}
                          </span>
                        </TableCell>
                        <TableCell>
                          {new Date(ring.created_at).toLocaleDateString()}
                        </TableCell>
                        <TableCell>
                          <div className="flex space-x-2">
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => toggleRingStatusMutation.mutate({ 
                                ringId: ring.id, 
                                active: !ring.active 
                              })}
                              disabled={toggleRingStatusMutation.isPending}
                            >
                              {ring.active ? <ToggleRight className="h-4 w-4" /> : <ToggleLeft className="h-4 w-4" />}
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => setAddingMember(ring)}
                            >
                              <UserPlus className="h-4 w-4" />
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => setEditingRing(ring)}
                            >
                              <Edit className="h-4 w-4" />
                            </Button>
                            <Button
                              size="sm"
                              variant="destructive"
                              onClick={() => {
                                if (confirm(`Are you sure you want to delete ring ${ring.id}?`)) {
                                  deleteRingMutation.mutate(ring.id);
                                }
                              }}
                              disabled={deleteRingMutation.isPending}
                            >
                              <Trash2 className="h-4 w-4" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              ) : (
                <div className="py-8 text-center text-muted-foreground">
                  No rings created yet. Create your first ring above.
                </div>
              )}
            </CardContent>
          </Card>

          {/* Add Member Modal */}
          {addingMember && (
            <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
              <Card className="w-full max-w-md">
                <CardHeader>
                  <CardTitle>Add Member to Ring {addingMember.id}</CardTitle>
                  <CardDescription>
                    Add a new public key to this ring
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="space-y-2">
                      <Label htmlFor="newMemberKey">Public Key (hex)</Label>
                      <Input
                        id="newMemberKey"
                        value={newMemberKey}
                        onChange={(e) => setNewMemberKey(e.target.value)}
                        placeholder="Enter public key in hex format"
                      />
                    </div>
                    
                    {availablePubKeys && availablePubKeys.length > 0 && (
                      <div className="space-y-2">
                        <Label>Available Public Keys</Label>
                        <div className="max-h-32 overflow-y-auto space-y-1">
                          {availablePubKeys.map((pk) => (
                            <button
                              key={pk.user_id + pk.public_key_hex}
                              type="button"
                              className="w-full text-left p-2 text-xs rounded border hover:bg-muted truncate"
                              onClick={() => setNewMemberKey(pk.public_key_hex)}
                              title={pk.public_key_hex}
                            >
                              {pk.public_key_hex}
                            </button>
                          ))}
                        </div>
                      </div>
                    )}
                    
                    <div className="flex justify-end space-x-2">
                      <Button
                        variant="outline"
                        onClick={() => {
                          setAddingMember(null);
                          setNewMemberKey('');
                        }}
                      >
                        Cancel
                      </Button>
                      <Button
                        onClick={() => {
                          if (newMemberKey.trim()) {
                            addMemberMutation.mutate({
                              ringId: addingMember.id,
                              publicKey: newMemberKey.trim()
                            });
                          }
                        }}
                        disabled={!newMemberKey.trim() || addMemberMutation.isPending}
                      >
                        {addMemberMutation.isPending ? 'Adding...' : 'Add Member'}
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          )}

          {/* Edit Ring Modal */}
          {editingRing && (
            <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
              <Card className="w-full max-w-2xl max-h-[80vh] overflow-y-auto">
                <CardHeader>
                  <CardTitle>Edit Ring {editingRing.id}</CardTitle>
                  <CardDescription>
                    Manage ring members and settings
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-6">
                    <div className="grid gap-4 md:grid-cols-2">
                      <div>
                        <Label>Genre</Label>
                        <p className="text-sm text-muted-foreground capitalize">{editingRing.genre}</p>
                      </div>
                      <div>
                        <Label>Epoch</Label>
                        <p className="text-sm text-muted-foreground">{editingRing.epoch}</p>
                      </div>
                    </div>

                    <div className="space-y-3">
                      <Label>Ring Members ({editingRing.member_count})</Label>
                      <div className="space-y-2 max-h-48 overflow-y-auto">
                        {ringDetails?.pubkeys && ringDetails.pubkeys.length > 0 ? (
                          ringDetails.pubkeys.map((pubkey: string, index: number) => (
                            <div key={index} className="flex items-center justify-between p-2 border rounded">
                              <span className="text-xs font-mono truncate flex-1 mr-2" title={pubkey}>
                                {pubkey}
                              </span>
                              <Button
                                size="sm"
                                variant="destructive"
                                onClick={() => {
                                  if (confirm(`Remove this member from the ring?`)) {
                                    removeMemberMutation.mutate({
                                      ringId: editingRing.id,
                                      publicKey: pubkey
                                    });
                                  }
                                }}
                                disabled={removeMemberMutation.isPending}
                              >
                                <UserMinus className="h-3 w-3" />
                              </Button>
                            </div>
                          ))
                        ) : (
                          <p className="text-sm text-muted-foreground">
                            No members found or loading...
                          </p>
                        )}
                      </div>
                    </div>
                    
                    <div className="flex justify-end space-x-2">
                      <Button
                        variant="outline"
                        onClick={() => setEditingRing(null)}
                      >
                        Close
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}