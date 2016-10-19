#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <Windows.h>

// Returns the base address of a specified module ( exe/dll )
// Throws a runtime_error if module couldn't be found
// Windows specific
inline uint8_t* GetModuleBaseAddress( const std::string& ModuleName_ )
{
	auto ModuleBase = reinterpret_cast< uint8_t* >( GetModuleHandle( ModuleName_.c_str( ) ) );

	if ( ModuleBase == nullptr )
		throw std::runtime_error( "ModuleBase is nullptr, couldn't find specified module" );

	return ModuleBase;
}

// Returns the module size of a specificied module ( exe/dll )
// Windows specific
inline size_t GetModuleSize( const uint8_t* BaseAddress_ )
{
	auto DosHeader = reinterpret_cast< const IMAGE_DOS_HEADER* >( BaseAddress_ );
	auto NTHeader = reinterpret_cast< const IMAGE_NT_HEADERS* >( BaseAddress_ + DosHeader->e_lfanew );
	return NTHeader->Signature == IMAGE_NT_SIGNATURE ? NTHeader->OptionalHeader.SizeOfImage : 0;
}

template< typename T, typename A >
T GetBytesAtAddress( A Address_ )
{
	return *reinterpret_cast< T* >( Address_ );
}

class Module
{
public:

	Module( const std::string& ModuleName_ )
		: m_ModuleName( ModuleName_ ),
		m_ModuleBase( GetModuleBaseAddress( ModuleName_ ) ),
		m_ModuleSize( GetModuleSize( m_ModuleBase ) )
	{
	}

	// Iterates over the specified module and compares the bytes of the module with a specified byte pattern
	// Once the pattern is found in the module, the address of the location of the pattern inside the module is reinterpret_casted to T and returned
	// If the pattern is not found, a nullptr is returned
	template< typename T >
	T FindPattern( const std::vector< uint16_t >& Pattern_ ) const
	{
		for ( auto Data = m_ModuleBase; Data <= ( m_ModuleBase + m_ModuleSize ) - Pattern_.size( ); ++Data )
			if ( [ & ]( )
			{
				for ( auto i = 0u; i < Pattern_.size( ); ++i )
				{
					if ( Data[ i ] != Pattern_[ i ] )
						if ( Pattern_[ i ] != 256u ) return false;
				}
				return true;
			}( ) ) return reinterpret_cast< T >( Data );
			return nullptr;
	}

	template< typename T >
	T FindPattern( const std::string& Pattern_ ) const
	{
		return FindPattern< T >( ConvertIDAPatternToByteVector( Pattern_ ) );
	}

private:

	// Converts an IDA-style byte pattern string to a vector of unsigned shorts
	// Skips spaces ( can be omitted ), exchanges '?' with 256/0x100 wildcard
	// "FC E8 ? ? ? ? 8B 3D" / "FC E8 ?? ?? ?? ?? 8B 3D"  =>  std::vector< uint16_t >{ 0xFC, 0xE8, 0x100, 0x100, 0x100, 0x100, 0x8B, 0x3D }
	static std::vector< uint16_t > ConvertIDAPatternToByteVector( const std::string& Pattern_ )
	{
		auto ByteBuffer = std::vector< uint16_t >{ };

		for ( auto i = Pattern_.cbegin( ); i != Pattern_.cend( ); ++i )
		{
			if ( *i == ' ' ) continue;

			if ( *i == '?' )
			{
				if ( *( i + 1 ) == '?' )
					++i;
				ByteBuffer.push_back( 256u );
			}
			else
			{
#pragma warning( suppress:4244 ) // conversion from 'long' to 'unsigned short', possible loss of data
				ByteBuffer.push_back( strtol( &Pattern_[ distance( Pattern_.cbegin( ), i ) ], nullptr, 16 ) );
				++i;
			}
		}

		return ByteBuffer;
	}


	const std::string m_ModuleName;
	uint8_t* m_ModuleBase;
	size_t m_ModuleSize;
};
