// comments...
// docs for file
package testdata

// docs for type declaration
type Person struct {
	// docs for field
	Age int
	// docs for field
	// Name is a name
	Name string
	// comments for nothing

	Account int // inline comments
	// comments for nothing

	// balance comment1
	// balance comment2
	Balance int // balance comment3

	// Bio comment
	Bio string `json:"bio"` // comment for bio
	// comments for nothing

	// comments for nothing too

	End string
}

// comments...

// docs for variable declaration
/* 123 */ /* 456 */
var (
	// docs for spec
	ints = 1
)

/* 123

   123
*/
// docs for function declaration
func docs() {}
