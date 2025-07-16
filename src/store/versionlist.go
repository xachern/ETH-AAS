package store

import (
	"bytes"
	"fmt"

	"github.com/RoaringBitmap/roaring/roaring64"
)

const WORKER_NUM = 4

type VersionList struct {
	bitmap *roaring64.Bitmap
}

func NewVersionList() *VersionList {
	return &VersionList{
		bitmap: roaring64.New(),
	}
}

func (vl *VersionList) AddVersion(blockNumber uint64) {
	vl.bitmap.Add(blockNumber)
}

func (vl *VersionList) MinVersion() uint64 {
	return vl.bitmap.Minimum()
}

func (vl *VersionList) MaxVersion() uint64 {
	return vl.bitmap.Maximum()
}

func (vl *VersionList) FindPrev(target uint64) (uint64, error) {
	if vl.bitmap.IsEmpty() || target < vl.bitmap.Minimum() {
		return 0, fmt.Errorf("no value found less than or equal to %d", target)
	}

	rangeBitmap := roaring64.New()
	rangeBitmap.AddRange(vl.bitmap.Minimum(), target+1)

	intersection := roaring64.And(vl.bitmap, rangeBitmap)

	if intersection.IsEmpty() {
		return 0, fmt.Errorf("no value found less than or equal to %d", target)
	}
	return intersection.Maximum(), nil
}

func (vl *VersionList) FindNext(target uint64) (uint64, error) {

	if vl.bitmap.IsEmpty() || target > vl.bitmap.Maximum() {
		return 0, fmt.Errorf("no value found greater than or equal to %d", target)
	}

	rangeBitmap := roaring64.New()
	rangeBitmap.AddRange(target, vl.bitmap.Maximum()+1)
	intersection := roaring64.And(vl.bitmap, rangeBitmap)

	if intersection.IsEmpty() {
		return 0, fmt.Errorf("no value found greater than or equal to %d", target)
	}
	return intersection.Minimum(), nil
}

func (vl *VersionList) ContainsVersion(blockNumber uint64) bool {
	return vl.bitmap.Contains(blockNumber)
}

func (vl *VersionList) GetRange(start, end uint64) []uint64 {
	rangeBitmap := roaring64.New()
	rangeBitmap.AddRange(start, end+1)
	// computes intersection of the bitmaps in parallel using 4 workers
	// result := roaring.ParAnd(vl.bitmap, rangeBitmap)
	result := roaring64.And(vl.bitmap, rangeBitmap)

	versions := result.ToArray()
	return versions
}

// GetBoundingVersions
// 1. If start<= min < max <= end, return all versions during [min,max]
// 2. If start <= min < end <= max, return all versions during [min,findNext(end)]
// 3. If min < start < max <= end , return all versions during [findPrev(start),max]
// 4. If min < start < end < max, return all versions during [findPrev(start),findNext(end)]
func (vl *VersionList) GetBoundingVersions(start, end uint64) ([]uint64, error) {
	if vl == nil {
		return nil, fmt.Errorf("version list is nil")
	}

	if start > end {
		return nil, fmt.Errorf("start version %d is greater than end version %d", start, end)
	}

	if vl.bitmap.IsEmpty() {
		return nil, fmt.Errorf("version list is empty")
	}

	min := vl.MinVersion()
	max := vl.MaxVersion()

	if start > max || end < min {
		// return empty list if the range is out of the version list
		return nil, nil
	}

	// Case 1: start <= min < max <= end
	if start <= min && max <= end {
		return vl.ToArray(), nil
	}

	// Case 2: start <= min < end <= max
	if start <= min && min < end && end <= max {
		next, err := vl.FindNext(end)
		if err != nil {
			return nil, err
		}
		return vl.GetRange(min, next), nil
	}

	// Case 3: min < start < max <= end
	if min < start && start < max && max <= end {
		prev, err := vl.FindPrev(start)
		if err != nil {
			return nil, err
		}
		return vl.GetRange(prev, max), nil
	}

	// Case 4: min < start < end < max
	if min < start && start < end && end < max {
		prev, err := vl.FindPrev(start)
		if err != nil {
			return nil, err
		}
		next, err := vl.FindNext(end)
		if err != nil {
			return nil, err
		}
		return vl.GetRange(prev, next), nil
	}

	return nil, fmt.Errorf("no value found between %d and %d", start, end)
}

func (vl *VersionList) Serialize() ([]byte, error) {
	var buf bytes.Buffer
	_, err := vl.bitmap.WriteTo(&buf)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize bitmap: %v", err)
	}
	return buf.Bytes(), nil
}

func DeserializeVersionlist(data []byte) (*VersionList, error) {
	bitmap := roaring64.New()
	_, err := bitmap.ReadFrom(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize bitmap: %v", err)
	}
	return &VersionList{bitmap: bitmap}, nil
}

func (vl *VersionList) Cardinality() uint64 {
	return vl.bitmap.GetCardinality()
}

func (vl *VersionList) ToArray() []uint64 {
	return vl.bitmap.ToArray()
}

func (vl *VersionList) Print() {
	it := vl.bitmap.Iterator()
	for it.HasNext() {
		fmt.Printf("%d ", it.Next())
	}
	fmt.Println()
}
