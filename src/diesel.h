#pragma once
#include <cstdint>
#include <cstdlib>


class Allocator {
public:
  virtual ~Allocator();
  virtual void* allocate(unsigned int size);
  virtual void* allocate_aligned(unsigned int size, unsigned int align);
  virtual void deallocate(void* ptr);
};
template<typename TFirst, typename TSecond> struct Pair {
  TFirst first;
  TSecond second;
};
template<typename TValue> struct Vector {
  unsigned int _size;
  unsigned int _capacity;
  TValue* _data;
  Allocator* _allocator;

  void set_capacity(size_t capacity)
  {
    if (capacity != this->_capacity) {
      TValue* new_buffer = nullptr;
      if(capacity) {
        new_buffer = (TValue*)this->_allocator->allocate_aligned(sizeof(TValue) * capacity, 8);
        memmove(new_buffer, this->_data, sizeof(TValue) * this->_size);
      }
      this->_allocator->deallocate(this->_data);
      this->_data = new_buffer;
      this->_capacity = capacity;
    }
  }

  TValue* begin() const { return _data; }
  TValue* end() const { return &_data[_size]; }
};
template<typename TKey, typename TValue> struct SortMap {
  char _less[0x4]; // std::_less
  Vector<Pair<TKey, TValue>> _data;
  bool _is_sorted;

  inline static unsigned int (SortMap<TKey, TValue>::* lower_bound_index_func)(const TKey* k);
  inline static unsigned int (SortMap<TKey, TValue>::* upper_bound_index_func)(const TKey* k);


  unsigned int lower_bound_index(const TKey* k) { return (this->*lower_bound_index_func)(k); }
  unsigned int upper_bound_index(const TKey* k) { return (this->*upper_bound_index_func)(k); }
};

struct PDTH_MSVC2008_string {
  PDTH_MSVC2008_string() { data[0] = 0; _Mysize = 0; _Myres = 15; }

  inline static void (PDTH_MSVC2008_string::* assign_func)(const char* _Ptr);
  inline static void (PDTH_MSVC2008_string::* assign_func_len)(const char* _Ptr, unsigned int len);
  void assign(const char* _Ptr)
  {
    (this->*assign_func)(_Ptr);
  }
  void assign(const char* _Ptr, unsigned int len)
  {
    (this->*assign_func_len)(_Ptr, len);
  }

  char PAD[3];
  union {
    char data[16];
    char* ptr;
  };
  unsigned int _Mysize;
  unsigned int _Myres;

  const char* get_str() const
  {
    if (_Myres > 15) {
      return ptr;
    }
    else {
      return data;
    }
  }
};
